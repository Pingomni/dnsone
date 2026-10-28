"""Dynamic DNS: RFC 2136 updates signed with TSIG, applied to MySQL like any other change.

dnsone-ddns listens on DNSONE_DDNS_LISTEN (127.0.0.1:5302) behind dnsdist, which sends it every UPDATE
message (Settings → DNS server → Dynamic DNS: from customers or from anyone) with a PROXY protocol
header naming the real client. BIND is never updated directly: MySQL stays the source of truth, so
an update is validated like an edit in the console, audited (actor "ddns:<key>"), versioned and
published by the zone generator.

Keys (Zone → Dynamic DNS) belong to one zone and may change only the names and record types they
list: e.g. 'home' A/AAAA for a router, '_acme-challenge' TXT for certbot's rfc2136 plugin, or '*.dyn'
for every name below dyn. Prerequisites follow RFC 2136 section 3.2; updates section 3.4, except that
"delete all records at a name" removes only the types the key may change. An update that touches
anything else is refused as a whole. Unsigned updates and bad signatures get REFUSED / NOTAUTH.

The same keys work with the dyndns2 HTTP protocol most routers offer as "custom" dynamic DNS
(GET /nic/update?hostname=…&myip=…, HTTP basic authentication with the key name and secret).
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hmac
import ipaddress
import re
import logging
import secrets
import signal
import struct
import threading
import time
from dataclasses import dataclass, field

import dns.exception
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.update
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from . import audit, logsetup, validation
from .config import get_settings
from .db import new_session
from .models import DdnsKey, Record, Zone
from .system import utcnow

log = logging.getLogger(__name__)

ALGORITHMS = {"hmac-sha256": dns.tsig.HMAC_SHA256, "hmac-sha512": dns.tsig.HMAC_SHA512, "hmac-sha384": dns.tsig.HMAC_SHA384,
              "hmac-sha224": dns.tsig.HMAC_SHA224, "hmac-sha1": dns.tsig.HMAC_SHA1}
# What a key may be allowed to change: never SOA, the apex NS records or DNSSEC data.
TYPES = ("A", "AAAA", "TXT", "CNAME", "MX", "SRV", "PTR", "CAA", "TLSA", "SSHFP", "HTTPS", "SVCB", "DS", "NS")
HEALTH_NAME = dns.name.from_text("health.ddns.dnsone.")
PROXY_SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


class Refused(Exception):
    def __init__(self, rcode: int, reason: str):
        super().__init__(reason)
        self.rcode = rcode
        self.reason = reason


# --------------------------------------------------------------------------- keys


def new_secret() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


def key_name(raw: str, zone: str) -> str:
    """TSIG key names are domain names; a single label is placed under the zone."""
    value = raw.strip().lower().rstrip(".")
    if not value:
        raise validation.ValidationError("name", "Give the key a name, e.g. router or certbot.")
    fqdn = value if "." in value else f"{value}.{zone}"
    validation.zone_name(fqdn, "name")
    return f"{fqdn}."


def clean_names(values: list[str], zone: str) -> list[str]:
    out = []
    for i, raw in enumerate(values):
        raw = raw.strip()
        if not raw:
            continue
        wildcard = raw.startswith("*.")
        owner = validation.owner_name(raw[2:] if wildcard else raw, zone, f"names.{i}")
        entry = f"*.{owner}" if wildcard and owner != "@" else ("*" if wildcard else owner)
        if entry not in out:
            out.append(entry)
    if not out:
        raise validation.ValidationError("names", "List the names the key may change, e.g. home, _acme-challenge or *.dyn.")
    return out


def clean_types(values: list[str]) -> list[str]:
    out = sorted({v.strip().upper() for v in values if v.strip()})
    bad = [t for t in out if t not in TYPES]
    if bad:
        raise validation.ValidationError("types", f"Keys cannot change {', '.join(bad)}; choose from {', '.join(TYPES)}.")
    if not out:
        raise validation.ValidationError("types", "Choose the record types the key may change.")
    return out


def clean_secret(raw: str) -> str:
    value = raw.strip()
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise validation.ValidationError("secret", "The secret is base64 (leave it empty to generate one).") from None
    if len(decoded) < 16:
        raise validation.ValidationError("secret", "Use a secret of at least 16 bytes (128 bits).")
    return value


def allowed(key: DdnsKey, owner: str, rtype: str) -> bool:
    """Whether the key may change `rtype` records at `owner` (relative to the zone)."""
    if rtype not in (key.types or []):
        return False
    if owner == "@" and rtype == "NS":
        return False
    for pattern in key.names or []:
        if pattern == owner:
            return True
        if pattern == "*" and owner != "@":
            return True
        if pattern.startswith("*.") and owner.endswith(pattern[1:]):
            return True
    return False


# --------------------------------------------------------------------------- applying an update


def _owner(name: dns.name.Name, zone: dns.name.Name) -> str:
    if name == zone:
        return "@"
    owner = name.relativize(zone).to_text().lower()
    # validation.owner_name reads "<zone>" and "x.<zone>" as the zone's own names (pasted without the final dot), so
    # example.com.example.com. would be stored at the apex: such a name is refused, never checked against the key's
    # patterns as something else.
    if _repeats_zone(owner, zone.to_text(omit_final_dot=True).lower()):
        raise Refused(dns.rcode.REFUSED, f"{name} repeats the zone name")
    return owner


def _repeats_zone(owner: str, zone: str) -> bool:
    return owner == zone or owner.endswith("." + zone)


def _record_fields(zone_name: str, owner: str, rd) -> tuple[str, str, str, int | None]:
    """An update's RDATA as DNSOne stores it (validated and normalised like a console edit)."""
    rtype = dns.rdatatype.to_text(rd.rdtype)
    priority = None
    if rtype in ("A", "AAAA"):
        value = rd.address
    elif rtype == "TXT":
        value = b"".join(rd.strings).decode("utf-8", errors="replace")
    elif rtype == "MX":
        priority, value = rd.preference, rd.exchange.to_text()
    elif rtype == "SRV":
        priority, value = rd.priority, f"{rd.weight} {rd.port} {rd.target.to_text()}"
    elif rtype in ("CNAME", "PTR", "NS"):
        value = rd.target.to_text()
    else:
        value = rd.to_text()
    return validation.record(zone_name, owner, rtype, value, priority)


def _class(rrset) -> int:
    """The RR class as sent: dnspython reports ANY and NONE (deletions, existence checks) in `deleting`."""
    return rrset.deleting if rrset.deleting is not None else rrset.rdclass


@dataclass
class Plan:
    add: list[tuple[str, str, str, int | None, int]] = field(default_factory=list)
    delete_ids: set[int] = field(default_factory=set)
    changes: list[str] = field(default_factory=list)


def apply_update(db: Session, msg: dns.update.UpdateMessage, key: DdnsKey, client: str) -> int:
    """Checks prerequisites and applies the update in one transaction. Returns the rcode."""
    zone_rr = msg.zone[0] if len(msg.zone) == 1 else None
    if zone_rr is None or zone_rr.rdtype != dns.rdatatype.SOA:
        raise Refused(dns.rcode.FORMERR, "the zone section must hold one SOA question")
    zone = db.scalar(select(Zone).where(Zone.id == key.zone_id).with_for_update())
    origin = dns.name.from_text(f"{zone.name}.")
    if zone_rr.name != origin:
        raise Refused(dns.rcode.NOTAUTH, f"key {key.name} is for {zone.name}, not {zone_rr.name}")
    if zone.status != "active":
        raise Refused(dns.rcode.REFUSED, f"{zone.name} is disabled")
    records = list(db.scalars(select(Record).where(Record.zone_id == zone.id)))
    live = [r for r in records if not r.disabled]

    def at(owner: str) -> list[Record]:
        return [r for r in live if r.name == owner]

    # Prerequisites (RFC 2136 3.2)
    wanted: dict[tuple[str, str], set[tuple]] = {}
    for rrset in msg.prerequisite:
        if not rrset.name.is_subdomain(origin):
            raise Refused(dns.rcode.NOTZONE, f"{rrset.name} is outside {zone.name}")
        owner = _owner(rrset.name, origin)
        rtype = dns.rdatatype.to_text(rrset.rdtype)
        present = at(owner)
        rdclass = _class(rrset)
        if rdclass == dns.rdataclass.ANY:
            if rrset.rdtype == dns.rdatatype.ANY:
                if not present and owner != "@":
                    return dns.rcode.NXDOMAIN
            elif not any(r.type == rtype for r in present) and not (owner == "@" and rtype == "SOA"):
                return dns.rcode.NXRRSET
        elif rdclass == dns.rdataclass.NONE:
            if rrset.rdtype == dns.rdatatype.ANY:
                if present or owner == "@":
                    return dns.rcode.YXDOMAIN
            elif any(r.type == rtype for r in present):
                return dns.rcode.YXRRSET
        else:
            for rd in rrset:
                try:
                    name, t, value, prio = _record_fields(zone.name, owner, rd)
                except validation.ValidationError:
                    return dns.rcode.NXRRSET
                wanted.setdefault((name, t), set()).add((value, prio))
    for (owner, rtype), values in wanted.items():
        have = {(r.value, r.priority) for r in at(owner) if r.type == rtype}
        if have != values:
            return dns.rcode.NXRRSET

    # Updates (RFC 2136 3.4): check everything first, then apply.
    plan = Plan()
    adds: list[tuple[str, str, str, int | None, int]] = []
    for rrset in msg.update:
        if not rrset.name.is_subdomain(origin):
            raise Refused(dns.rcode.NOTZONE, f"{rrset.name} is outside {zone.name}")
        owner = _owner(rrset.name, origin)
        rtype = dns.rdatatype.to_text(rrset.rdtype)
        rdclass = _class(rrset)
        if rdclass == dns.rdataclass.ANY:
            if rrset.rdtype == dns.rdatatype.ANY:
                # Every record at the name that the key may change.
                doomed = [r for r in at(owner) if allowed(key, owner, r.type)]
                if not doomed and not any(allowed(key, owner, t) for t in key.types or []):
                    raise Refused(dns.rcode.REFUSED, f"key {key.name} may not change {owner}")
                plan.delete_ids |= {r.id for r in doomed}
                plan.changes.append(f"delete {owner} (all its {', '.join(sorted({r.type for r in doomed})) or 'no'} records)")
            else:
                if not allowed(key, owner, rtype):
                    raise Refused(dns.rcode.REFUSED, f"key {key.name} may not change {owner} {rtype}")
                plan.delete_ids |= {r.id for r in at(owner) if r.type == rtype}
                plan.changes.append(f"delete {owner} {rtype}")
        elif rdclass == dns.rdataclass.NONE:
            if not allowed(key, owner, rtype):
                raise Refused(dns.rcode.REFUSED, f"key {key.name} may not change {owner} {rtype}")
            for rd in rrset:
                name, t, value, prio = _record_fields(zone.name, owner, rd)
                plan.delete_ids |= {r.id for r in at(name) if r.type == t and r.value == value and r.priority == prio}
                plan.changes.append(f"delete {name} {t} {value}")
        elif rdclass == dns.rdataclass.IN:
            if rrset.rdtype == dns.rdatatype.ANY:
                raise Refused(dns.rcode.FORMERR, "cannot add records of type ANY")
            if not allowed(key, owner, rtype):
                raise Refused(dns.rcode.REFUSED, f"key {key.name} may not change {owner} {rtype}")
            ttl = min(max(int(rrset.ttl), validation.MIN_TTL), validation.MAX_TTL)
            for rd in rrset:
                try:
                    name, t, value, prio = _record_fields(zone.name, owner, rd)
                except validation.ValidationError as exc:
                    raise Refused(dns.rcode.REFUSED, f"{owner} {rtype}: {exc.message}") from None
                adds.append((name, t, value, prio, ttl))
        else:
            raise Refused(dns.rcode.FORMERR, "unexpected class in the update section")

    # Records that stay, then the additions; an add that conflicts (CNAME rules) is ignored (RFC 2136 3.4.2.2).
    remaining = [r for r in live if r.id not in plan.delete_ids]
    types: dict[str, set[str]] = {}
    keys = {(r.name, r.type, r.priority, r.value): r for r in records if r.id not in plan.delete_ids}
    for r in remaining:
        types.setdefault(r.name, set()).add(r.type)
    for name, t, value, prio, ttl in adds:
        existing = keys.get((name, t, prio, value))
        if existing is not None:
            if existing.ttl != ttl or existing.disabled:
                existing.ttl, existing.disabled = ttl, False
                plan.changes.append(f"ttl {name} {t} {value} {ttl}")
            continue
        if validation.conflict(name, t, types.get(name, set())):
            plan.changes.append(f"ignored {name} {t} {value} (conflicts with the records there)")
            continue
        types.setdefault(name, set()).add(t)
        row = Record(zone_id=zone.id, name=name, type=t, value=value, ttl=ttl, priority=prio, comment=f"dynamic DNS ({key.name.rstrip('.')})")
        db.add(row)
        keys[(name, t, prio, value)] = row
        plan.add.append((name, t, value, prio, ttl))
        plan.changes.append(f"add {name} {ttl} {t} {'' if prio is None else f'{prio} '}{value}")
    touched = bool(plan.add or plan.delete_ids or any(c.startswith("ttl ") for c in plan.changes))
    if any(r.name == "@" and r.type == "NS" for r in records if r.id in plan.delete_ids):
        raise Refused(dns.rcode.REFUSED, "the apex NS records cannot be removed")
    if plan.delete_ids:
        for r in records:
            if r.id in plan.delete_ids:
                db.delete(r)
    key.last_used_at, key.last_used_ip = utcnow(), client[:45]
    if touched:
        db.flush()
        db.execute(update(Zone).where(Zone.id == zone.id).values(revision=Zone.revision + 1, publish_state="pending"))
        audit.record(db, f"ddns:{key.name.rstrip('.')}"[:64], "zone.dynamic_update", "zone", zone.id,
                     {"name": zone.name, "key": key.name, "changes": plan.changes[:200]}, client)
    db.commit()
    if touched:
        # Answer now; the zone generator publishes (and retries on its timer if that fails).
        from .zonegen import publish_in_background
        threading.Thread(target=publish_in_background, args=(zone.id,), daemon=True).start()
    return dns.rcode.NOERROR


def find_key(db: Session, name: dns.name.Name) -> DdnsKey | None:
    return db.scalar(select(DdnsKey).where(DdnsKey.name == name.to_text().lower(), DdnsKey.enabled.is_(True)))


def tsig_key(row: DdnsKey) -> dns.tsig.Key:
    return dns.tsig.Key(row.name, row.secret, ALGORITHMS[row.algorithm])


def handle(wire: bytes, client: str) -> bytes | None:
    """One DNS message from dnsdist; returns the response (None to drop)."""
    db = new_session()
    found: dict[str, DdnsKey] = {}

    def keyring(_message, name: dns.name.Name):
        row = find_key(db, name)
        if row is None:
            return None
        found["key"] = row
        return tsig_key(row)

    try:
        try:
            msg = dns.message.from_wire(wire, keyring=keyring)
        except (dns.message.UnknownTSIGKey, dns.tsig.BadSignature, dns.tsig.BadTime, dns.tsig.BadKey, dns.tsig.BadAlgorithm) as exc:
            log.info("update from %s refused: %s", client, exc.__class__.__name__)
            plain = _unsigned(wire)
            if plain is None:
                return None
            error = {dns.tsig.BadTime: dns.rcode.BADTIME}.get(type(exc), dns.rcode.BADKEY if isinstance(exc, (dns.message.UnknownTSIGKey, dns.tsig.BadKey, dns.tsig.BadAlgorithm)) else dns.rcode.BADSIG)
            return _tsig_error(plain, error)
        except dns.exception.DNSException:
            return None
        if msg.opcode() != dns.opcode.UPDATE:
            # dnsdist's health check, or a query that should not have come here.
            response = dns.message.make_response(msg)
            response.set_rcode(dns.rcode.NOERROR if msg.question and msg.question[0].name == HEALTH_NAME else dns.rcode.REFUSED)
            return response.to_wire()
        response = dns.message.make_response(msg)
        key = found.get("key")
        if key is None or not msg.had_tsig:
            log.info("unsigned update from %s refused", client)
            response.set_rcode(dns.rcode.REFUSED)
            return response.to_wire()
        try:
            rcode = apply_update(db, msg, key, client)
        except Refused as exc:
            db.rollback()
            log.info("update with key %s from %s refused: %s", key.name, client, exc.reason)
            rcode = exc.rcode
        except validation.ValidationError as exc:
            db.rollback()
            log.info("update with key %s from %s refused: %s", key.name, client, exc.message)
            rcode = dns.rcode.REFUSED
        response.set_rcode(rcode)
        return response.to_wire()
    except Exception:  # noqa: BLE001 - never crash the listener
        db.rollback()
        log.exception("update from %s failed", client)
        plain = _unsigned(wire)
        return _reply(plain, dns.rcode.SERVFAIL) if plain is not None else None
    finally:
        db.close()


def _unsigned(wire: bytes) -> dns.message.Message | None:
    try:
        return dns.message.from_wire(wire, keyring=False)
    except dns.exception.DNSException:
        return None


def _tsig_error(msg: dns.message.Message, error: int) -> bytes:
    """NOTAUTH with a TSIG record that carries the error and no MAC (RFC 8945 5.3.2): the client learns why."""
    import dns.rdtypes.ANY.TSIG
    request = msg.tsig[0] if msg.tsig else None
    msg.keyring = None
    response = dns.message.make_response(msg)
    response.set_rcode(dns.rcode.NOTAUTH)
    wire = bytearray(response.to_wire())
    if request is None:
        return bytes(wire)
    now = int(time.time())
    other = struct.pack("!HI", (now >> 32) & 0xFFFF, now & 0xFFFFFFFF) if error == dns.rcode.BADTIME else b""
    rdata = dns.rdtypes.ANY.TSIG.TSIG(dns.rdataclass.ANY, dns.rdatatype.TSIG, request.algorithm, request.time_signed if error != dns.rcode.BADTIME else now,
                                      request.fudge, b"", msg.id, error, other)
    owner = msg.tsig.name.to_wire()
    body = rdata.to_digestable()
    wire += owner + struct.pack("!HHIH", dns.rdatatype.TSIG, dns.rdataclass.ANY, 0, len(body)) + body
    struct.pack_into("!H", wire, 10, struct.unpack_from("!H", wire, 10)[0] + 1)
    return bytes(wire)


def _reply(msg: dns.message.Message, rcode: int) -> bytes:
    msg.keyring = None
    response = dns.message.make_response(msg)
    response.set_rcode(rcode)
    return response.to_wire()


# --------------------------------------------------------------------------- dyndns2 (HTTP)


def dyndns2(db: Session, auth_name: str, secret: str, hostname: str, addresses: list[str], client: str) -> str:
    """One /nic/update request; returns the dyndns2 answer ("good IP", "nochg IP", "badauth", ...)."""
    name = auth_name.strip().lower().rstrip(".")
    key = db.scalar(select(DdnsKey).where(DdnsKey.name.in_((f"{name}.",)), DdnsKey.enabled.is_(True))) if name else None
    if key is None and name and "." not in name and re.fullmatch(r"[a-z0-9_-]+", name):
        # Keys of a single label are stored under their zone: router -> router.example.com. Several zones may each
        # have a "router": the one whose secret matches is the key (another account's key can never shadow it).
        rows = db.execute(select(DdnsKey, Zone.name).join(Zone, Zone.id == DdnsKey.zone_id)
                          .where(DdnsKey.name.like(name.replace("_", "\\_") + ".%", escape="\\"), DdnsKey.enabled.is_(True)).limit(50)).all()
        own = [k for k, zname in rows if k.name == f"{name}.{zname}."]
        key = next((k for k in own if hmac.compare_digest(k.secret, secret.strip())), None)
    if key is None or not hmac.compare_digest(key.secret, secret.strip()):
        return "badauth"
    zone = db.get(Zone, key.zone_id)
    host = hostname.strip().lower().rstrip(".")
    if not host or "." not in host:
        return "notfqdn"
    if host != zone.name and not host.endswith(f".{zone.name}"):
        return "nohost"
    owner = "@" if host == zone.name else host[: -(len(zone.name) + 1)]
    if _repeats_zone(owner, zone.name):
        return "nohost"
    parsed = []
    for raw in addresses:
        try:
            parsed.append(ipaddress.ip_address(raw.strip()))
        except ValueError:
            return "dnserr"
    if not parsed:
        return "dnserr"
    for address in parsed:
        if not allowed(key, owner, "AAAA" if address.version == 6 else "A"):
            return "nohost"
    upd = dns.update.UpdateMessage(f"{zone.name}.")
    for version, rtype in ((4, "A"), (6, "AAAA")):
        mine = [str(a) for a in parsed if a.version == version]
        if mine:
            current = {r.value for r in db.scalars(select(Record).where(Record.zone_id == zone.id, Record.name == owner, Record.type == rtype, Record.disabled.is_(False)))}
            if current == set(mine):
                continue
            upd.delete(host + ".", rtype)
            for a in mine:
                upd.add(host + ".", 60, rtype, a)
    shown = ",".join(str(a) for a in parsed)
    if not upd.update:
        key.last_used_at, key.last_used_ip = utcnow(), client[:45]
        db.commit()
        return f"nochg {shown}"
    try:
        rcode = apply_update(db, upd, key, client)
    except (Refused, validation.ValidationError):
        db.rollback()
        return "dnserr"
    return f"good {shown}" if rcode == dns.rcode.NOERROR else "dnserr"


# --------------------------------------------------------------------------- the listener


def strip_proxy(data: bytes) -> tuple[str | None, bytes]:
    """Removes a PROXY protocol v2 header; returns (client address, rest)."""
    if not data.startswith(PROXY_SIGNATURE) or len(data) < 16:
        return None, data
    ver_cmd, family, length = data[12], data[13], struct.unpack("!H", data[14:16])[0]
    body, rest = data[16 : 16 + length], data[16 + length :]
    client = None
    if ver_cmd & 0x0F == 1:
        if family >> 4 == 1 and len(body) >= 12:
            client = str(ipaddress.IPv4Address(body[0:4]))
        elif family >> 4 == 2 and len(body) >= 36:
            client = str(ipaddress.IPv6Address(body[0:16]))
    return client, rest


class UdpServer(asyncio.DatagramProtocol):
    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        client, wire = strip_proxy(data)
        asyncio.get_running_loop().create_task(self._answer(wire, client or addr[0], addr))

    async def _answer(self, wire: bytes, client: str, addr) -> None:
        response = await asyncio.to_thread(handle, wire, client)
        if response is not None:
            self.transport.sendto(response, addr)


async def tcp_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")[0]
    client = peer
    try:
        head = await reader.readexactly(2)
        if head == PROXY_SIGNATURE[:2]:
            rest = await reader.readexactly(14)
            length = struct.unpack("!H", rest[12:14])[0]
            header = head + rest + await reader.readexactly(length)
            client = strip_proxy(header)[0] or peer
            head = await reader.readexactly(2)
        while True:
            (size,) = struct.unpack("!H", head)
            wire = await reader.readexactly(size)
            response = await asyncio.to_thread(handle, wire, client)
            if response is None:
                break
            writer.write(struct.pack("!H", len(response)) + response)
            await writer.drain()
            head = await reader.readexactly(2)
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        writer.close()


async def serve() -> None:
    s = get_settings()
    host, _, port = s.ddns_listen.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(UdpServer, local_addr=(host, int(port)))
    server = await asyncio.start_server(tcp_connection, host, int(port), reuse_address=True)
    log.info("listening on %s:%s (UDP and TCP)", host, port)
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    transport.close()
    server.close()


def main() -> int:
    logsetup.setup("ddns")
    asyncio.run(serve())
    return 0
