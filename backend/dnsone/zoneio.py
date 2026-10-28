"""Zone import: a BIND zone file or a zone transfer (AXFR) -> DNSOne records.

Every imported record passes through validation.record(), as if it had been typed in the console,
so what lands in MySQL is exactly what the API would have stored. Anything DNSOne does not manage
is reported instead of imported:
- the SOA becomes the zone's SOA fields (when a zone is created from the file);
- DNSSEC records (RRSIG, NSEC, DNSKEY, ...) are dropped: BIND signs zones itself (zonegen);
- types DNSOne does not support, names outside the zone and invalid records are listed with the reason.

TTLs outside DNSOne's 60–604800 s range are clamped, with a warning. A TTL equal to the zone's default
is stored as "default" (NULL), so changing the zone default later moves those records with it.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field

import dns.exception
import dns.grange
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.xfr
import dns.zone

from . import validation

MAX_RECORDS = 100_000
AXFR_TIMEOUT = 30

# Managed by BIND when DNSOne signs a zone; never imported.
DNSSEC_TYPES = {"RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DNSKEY", "CDS", "CDNSKEY", "ZONEMD", "TYPE65534"}

TSIG_ALGORITHMS = {
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
    "hmac-sha1": dns.tsig.HMAC_SHA1,
    "hmac-md5": dns.tsig.HMAC_MD5,
}


@dataclass
class ImportedRecord:
    name: str
    type: str
    value: str
    ttl: int | None
    priority: int | None

    @property
    def key(self) -> tuple:
        return (self.name, self.type, self.priority, self.value)

    def out(self) -> dict:
        return {"name": self.name, "type": self.type, "value": self.value, "ttl": self.ttl, "priority": self.priority}


@dataclass
class ParsedZone:
    origin: str
    records: list[ImportedRecord] = field(default_factory=list)
    soa: dict | None = None
    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dnssec_dropped: int = 0

    def apex_ns(self) -> list[str]:
        return [r.value for r in self.records if r.name == "@" and r.type == "NS"]


def _clamp_ttl(ttl: int, where: str, warnings: list[str]) -> int:
    clamped = min(max(int(ttl), validation.MIN_TTL), validation.MAX_TTL)
    if clamped != ttl:
        warnings.append(f"{where}: TTL {ttl} changed to {clamped} (DNSOne allows {validation.MIN_TTL}–{validation.MAX_TTL} s)")
    return clamped


def _value(rtype: str, rd) -> tuple[str, int | None]:
    """RDATA as DNSOne stores it: (value, priority). Names are absolute (the zone is not relativized)."""
    if rtype == "TXT":
        return b"".join(rd.strings).decode("utf-8"), None
    if rtype == "MX":
        return rd.exchange.to_text(), rd.preference
    if rtype == "SRV":
        return f"{rd.weight} {rd.port} {rd.target.to_text()}", rd.priority
    return rd.to_text(), None


def _convert(zone: dns.zone.Zone, origin: str) -> ParsedZone:
    out = ParsedZone(origin=origin)
    apex = dns.name.from_text(f"{origin}.")
    seen: set[tuple] = set()
    ttls: list[tuple[ImportedRecord, int]] = []
    for name, node in sorted(zone.nodes.items(), key=lambda item: item[0]):
        if not name.is_subdomain(apex):
            out.skipped.append(f"{name.to_text()}: outside the zone {origin}")
            continue
        owner = name.relativize(apex).to_text()
        for rdataset in node.rdatasets:
            rtype = dns.rdatatype.to_text(rdataset.rdtype)
            if rdataset.rdclass != dns.rdataclass.IN:
                out.skipped.append(f"{owner} {rtype}: class {dns.rdataclass.to_text(rdataset.rdclass)} is not imported")
                continue
            if rtype in DNSSEC_TYPES:
                out.dnssec_dropped += len(rdataset)
                continue
            if rtype == "SOA":
                if owner == "@":
                    soa = rdataset[0]
                    out.soa = {"mname": soa.mname.to_text(), "rname": soa.rname.to_text(), "serial": soa.serial,
                               "refresh": soa.refresh, "retry": soa.retry, "expire": soa.expire, "minimum": soa.minimum,
                               "ttl": rdataset.ttl}
                else:
                    out.skipped.append(f"{owner} SOA: an SOA record below the apex (a zone cut) is not imported")
                continue
            if rtype not in validation.RECORD_TYPES:
                out.skipped.append(f"{owner} {rtype}: DNSOne does not manage {rtype} records ({len(rdataset)} skipped)")
                continue
            for rd in rdataset:
                try:
                    raw, priority = _value(rtype, rd)
                    name_, type_, value, priority = validation.record(origin, owner, rtype, raw, priority)
                except UnicodeDecodeError:
                    out.skipped.append(f"{owner} TXT: the text is not UTF-8")
                    continue
                except validation.ValidationError as exc:
                    out.skipped.append(f"{owner} {rtype} {rd.to_text()[:80]}: {exc.message}")
                    continue
                rec = ImportedRecord(name=name_, type=type_, value=value, ttl=None, priority=priority)
                if rec.key in seen:
                    continue
                seen.add(rec.key)
                out.records.append(rec)
                ttls.append((rec, rdataset.ttl))
                if len(out.records) > MAX_RECORDS:
                    raise validation.ValidationError("text", f"The zone has more than {MAX_RECORDS:,} records; split it or ask for a bigger limit.")
    for rec, ttl in ttls:
        rec.ttl = _clamp_ttl(ttl, f"{rec.name} {rec.type}", out.warnings)
    return out


def default_ttl(parsed: ParsedZone) -> int:
    """The most common TTL: the zone's default when a zone is created from the file."""
    counts = Counter(r.ttl for r in parsed.records if r.ttl is not None)
    return counts.most_common(1)[0][0] if counts else 3600


def apply_default_ttl(parsed: ParsedZone, zone_default: int) -> None:
    for r in parsed.records:
        if r.ttl == zone_default:
            r.ttl = None


def parse_text(text: str, origin: str, default_ttl: int = 3600) -> ParsedZone:
    """A zone file in BIND syntax ($ORIGIN, $TTL, relative names, parentheses, comments).

    Pasted records without a $TTL line (or TTL of their own) get default_ttl, the zone's default.
    """
    if not text.strip():
        raise validation.ValidationError("text", "Paste the zone file, or choose a file.")
    if "$INCLUDE" in text.upper():
        raise validation.ValidationError("text", "$INCLUDE is not supported: paste the included file's records into this one.")
    # $GENERATE expands before the record limit is checked: count its ranges first.
    generated = 0
    for match in re.finditer(r"^\s*\$GENERATE\s+(\S+)", text, flags=re.M | re.I):
        try:
            start, stop, step = dns.grange.from_text(match.group(1))
        except Exception:
            raise validation.ValidationError("text", f"A $GENERATE range could not be read: {match.group(1)[:40]}") from None
        generated += (stop - start) // step + 1
        if generated > MAX_RECORDS:
            raise validation.ValidationError("text", f"$GENERATE would create more than {MAX_RECORDS:,} records.")
    # The ${offset,width,base} modifier pads the number to `width` characters before the name is checked.
    for modifier in re.finditer(r"\$\{([^}]*)\}", "\n".join(m.group(0) for m in re.finditer(r"^\s*\$GENERATE\b.*$", text, flags=re.M | re.I))):
        parts = modifier.group(1).split(",")
        if len(parts) > 3 or not re.fullmatch(r"[+-]?\d{1,10}", parts[0].strip() or "0") or (len(parts) > 1 and not re.fullmatch(r"\d{1,2}", parts[1].strip())):
            raise validation.ValidationError("text", f"A $GENERATE modifier is not valid: ${{{modifier.group(1)[:20]}}} (width at most 63).")
        if len(parts) > 1 and int(parts[1]) > 63:
            raise validation.ValidationError("text", "A $GENERATE width is at most 63.")
    if not re.search(r"^\s*\$TTL\b", text, flags=re.M | re.I):
        text = f"$TTL {default_ttl}\n{text}"
    try:
        zone = dns.zone.from_text(text, origin=f"{origin}.", relativize=False, check_origin=False, rdclass=dns.rdataclass.IN)
    except dns.exception.SyntaxError as exc:
        raise validation.ValidationError("text", f"The zone file could not be read: {exc}") from None
    except (dns.exception.DNSException, ValueError) as exc:
        reason = str(exc) or exc.__class__.__name__
        if "CNAME" in reason:
            reason = "a name has a CNAME and other records; a CNAME must be the only record at its name"
        raise validation.ValidationError("text", f"The zone file could not be read: {reason}.") from None
    return _convert(zone, origin)


def fetch_axfr(origin: str, server: str, port: int = 53, tsig_name: str = "", tsig_secret: str = "",
               tsig_algorithm: str = "hmac-sha256") -> ParsedZone:
    """Transfers the zone from another server (the old DNS server, before switching to DNSOne)."""
    try:
        address = str(validation.plain_ip(server.strip()))
    except ValueError:
        raise validation.ValidationError("axfr.server", "Enter the IP address of the server to transfer from.") from None
    ip = ipaddress.ip_address(address)
    # ::ffff:127.0.0.1 connects to 127.0.0.1: judge the IPv4 address it carries.
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        # This server's own daemons trust connections from itself (BIND's catalog, dnsdist): an import never uses them.
        raise validation.ValidationError("axfr.server", "Enter the address of the other server, not this one.")
    if not 1 <= int(port) <= 65535:
        raise validation.ValidationError("axfr.port", "Enter a port between 1 and 65535.")
    keyring, keyname, algorithm = None, None, None
    if tsig_name.strip() or tsig_secret.strip():
        if tsig_algorithm not in TSIG_ALGORITHMS:
            raise validation.ValidationError("axfr.tsig_algorithm", f"Choose one of: {', '.join(TSIG_ALGORITHMS)}.")
        try:
            keyname = dns.name.from_text(tsig_name.strip())
            keyring = dns.tsigkeyring.from_text({tsig_name.strip(): tsig_secret.strip()})
        except Exception:  # noqa: BLE001 - a bad name or base64 secret
            raise validation.ValidationError("axfr.tsig_secret", "Enter the TSIG key name and its base64 secret, as in the server's key statement.") from None
        algorithm = TSIG_ALGORITHMS[tsig_algorithm]
    try:
        zone = dns.zone.from_xfr(
            dns.query.xfr(address, f"{origin}.", port=int(port), timeout=AXFR_TIMEOUT, lifetime=AXFR_TIMEOUT * 4,
                          keyring=keyring, keyname=keyname, keyalgorithm=algorithm or dns.tsig.default_algorithm, relativize=False),
            relativize=False, check_origin=False)
    except dns.xfr.TransferError as exc:
        raise validation.ValidationError("axfr.server", f"{address} refused the transfer ({dns.rcode.to_text(exc.rcode)}). Allow transfers to this server (allow-transfer) and try again.") from None
    except dns.exception.FormError as exc:
        raise validation.ValidationError("axfr.server", f"{address} did not send a zone transfer for {origin} ({exc}).") from None
    except (dns.exception.DNSException, OSError, EOFError) as exc:
        raise validation.ValidationError("axfr.server", f"The transfer from {address}:{port} failed: {exc or exc.__class__.__name__}") from None
    return _convert(zone, origin)


# --------------------------------------------------------------------------- bulk reverse DNS

MAX_REVERSE = 65536


def reverse_zone_family(zone: str) -> int | None:
    if zone.endswith(".in-addr.arpa"):
        return 4
    if zone.endswith(".ip6.arpa"):
        return 6
    return None


def _placeholders(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> dict[str, str]:
    if address.version == 4:
        a, b, c, d = str(address).split(".")
        return {"a": a, "b": b, "c": c, "d": d, "ip": f"{a}-{b}-{c}-{d}"}
    return {"ip": address.exploded.replace(":", "-")}


def reverse_names(zone: str, network: str, template: str) -> list[tuple[str, str, str]]:
    """PTR records for every address of `network` in reverse zone `zone`: (owner, address, host.).

    template is the host name, with {a}.{b}.{c}.{d} (the IPv4 octets) or {ip} (the address with dashes,
    IPv6 written out in full): e.g. pool-{a}-{b}-{c}-{d}.isp.example or {ip}.dyn.isp.example.
    """
    family = reverse_zone_family(zone)
    if family is None:
        raise validation.ValidationError("network", "Generate reverse DNS in a reverse zone (…in-addr.arpa or …ip6.arpa).")
    try:
        net = ipaddress.ip_network(network.strip(), strict=False)
    except ValueError:
        raise validation.ValidationError("network", "Enter a subnet such as 192.0.2.0/24 or 2001:db8::/120.") from None
    if net.version != family:
        raise validation.ValidationError("network", f"{zone} holds IPv{family} reverse DNS; enter an IPv{family} subnet.")
    if net.num_addresses > MAX_REVERSE:
        hint = "/16" if family == 4 else "/112"
        raise validation.ValidationError("network", f"At most {MAX_REVERSE:,} addresses at a time ({hint}); generate a bigger range in parts.")
    for edge in (net[0], net[-1]):
        if not edge.reverse_pointer.endswith(f".{zone}"):
            raise validation.ValidationError("network", f"{net} is not inside {zone}: its reverse names would belong to another zone.")
    template = template.strip()
    if not template:
        raise validation.ValidationError("template", "Enter the host name pattern, e.g. pool-{a}-{b}-{c}-{d}.isp.example.")
    sample = _placeholders(net[0])
    try:
        template.format_map(sample)
    except (KeyError, IndexError, ValueError):
        allowed = "{a} {b} {c} {d} {ip}" if family == 4 else "{ip}"
        raise validation.ValidationError("template", f"Use only these placeholders: {allowed}.") from None
    if "{" not in template:
        raise validation.ValidationError("template", "Put a placeholder such as {ip} in the pattern, so every address gets its own name.")
    if "." not in template.rstrip("."):
        raise validation.ValidationError("template", "Enter a full host name, e.g. {ip}.dyn.isp.example.")
    out = []
    for address in net:
        host = template.format_map(_placeholders(address))
        try:
            fqdn = validation.absolute_name(host if host.endswith(".") else f"{host}.", zone, "template", hostname=True)
        except validation.ValidationError as exc:
            raise validation.ValidationError("template", f"{host}: {exc.message}") from None
        owner = address.reverse_pointer[: -(len(zone) + 1)]
        out.append((owner, str(address), fqdn))
    return out
