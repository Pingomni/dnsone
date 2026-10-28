"""Zone generator: MySQL -> BIND zone files -> rndc.

Publishing one zone:
  1. render the zone from MySQL with the next YYYYMMDDnn serial;
  2. write it to a temporary file beside the live one and run named-checkzone on it;
     if that fails the live file is untouched and the zone is marked `error`;
  3. move it into place (the old file is kept as <zone>.zone.prev);
  4. `rndc reload <zone>` (or `rndc reconfig` for a zone BIND does not know yet), then ask BIND for the
     SOA serial; if BIND did not load the new serial, put the previous file back and reload again.

The generated include (zones.conf), the Recursor forward-zones file and the dnsdist list of
authoritative zones are rewritten whenever the set of active zones changes. zones.conf is checked
with named-checkconf before `rndc reconfig`, and restored if the check fails.

All publishing runs under a MySQL advisory lock, so API workers, the reconcile timer and the CLI
never write the same files at once.

DNSSEC: a zone with signing on gets `dnssec-policy "dnsone"` and inline signing in zones.conf. DNSOne
still writes the unsigned file; BIND keeps the keys (DNSONE_BIND_KEY_DIR), writes <zone>.zone.signed
beside it and serves that, re-signing on its own. A signed zone's served serial can run ahead of the
file's (BIND bumps it when it re-signs), so its next file serial is taken above the served one, and a
publish counts as loaded once BIND serves that serial or a later one. Turning signing off moves the
zone to `dnssec-policy insecure`, which removes the signatures safely while resolvers still hold the DS.

ALIAS records: a name (often the apex) that answers with the addresses of another host, like a
CNAME that may share its name. BIND has no such type, so each publish resolves the target and writes
its A/AAAA records instead: from MySQL when the target is in a hosted zone, otherwise from the
resolvers in DNSONE_ALIAS_RESOLVERS (default: /etc/resolv.conf). The answers are kept in
zones.alias_cache; a target that cannot be resolved keeps its last answer, and the reconcile timer
republishes a zone when its targets' addresses change.

History: every publish that changed the zone stores a version (history.py) to compare and roll back to.

Clustering (Phase 2): with secondaries listed in Settings → Cluster, the primary also serves a
catalog zone (RFC 9432) naming every hosted zone, notifies the secondaries and lets them transfer;
BIND secondaries configured with `catalog-zones` (dnsone-ctl cluster secondary-config) then add and
drop zones by themselves. A node with DNSONE_ROLE=replica never publishes: its BIND is such a
secondary, and replica_sync() keeps its Recursor and dnsdist zone lists in line with MySQL.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

import dns.exception
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from . import dnssec, history, validation
from .edition import pro

transfers = pro("transfers")
from .config import Settings, get_settings
from .db import NamedLock, new_session
from .models import Record, Setting, Zone
from .system import CommandError, atomic_write, utcnow, fsync_dir, replace_keeping_previous, restore_previous, run, write_temp

log = logging.getLogger(__name__)

# Files BIND writes beside a zone file (journals, inline signing); removed with the zone.
ZONE_FILE_SUFFIXES = (".zone", ".zone.prev", ".zone.jnl", ".zone.signed", ".zone.signed.jnl", ".zone.jbk")

# Signing policy for DNSOne's signed zones: one ECDSA P-256 combined signing key (algorithm 13, what
# registrars and resolvers expect today) that does not roll by itself, so the DS at the parent only
# changes when an operator rolls the key (dnssec.py); NSEC3 without extra iterations or salt (RFC 9276).
# BIND publishes CDS/CDNSKEY for the key once its DNSKEY has reached every resolver (dnskey-ttl +
# publish-safety + zone-propagation-delay), so parents that scan for them (RFC 8078) update the DS.
def dnssec_policy(s: Settings) -> str:
    return f"""dnssec-policy "dnsone" {{
    keys {{ csk key-directory lifetime unlimited algorithm ecdsap256sha256; }};
    nsec3param iterations 0 optout no salt-length 0;
    max-zone-ttl {s.dnssec_max_zone_ttl};
    dnskey-ttl {s.dnssec_dnskey_ttl};
    publish-safety {s.dnssec_publish_safety};
    retire-safety {s.dnssec_publish_safety};
    zone-propagation-delay {s.dnssec_propagation_delay};
    parent-ds-ttl {s.dnssec_parent_ds_ttl};
    parent-propagation-delay {s.dnssec_parent_propagation_delay};
}};"""

TYPE_ORDER = {"NS": 0, "DS": 1, "A": 2, "AAAA": 3, "ALIAS": 3, "MX": 4, "TXT": 5, "CAA": 6, "HTTPS": 7, "SVCB": 8, "SRV": 9, "NAPTR": 10, "TLSA": 11, "SSHFP": 12, "CNAME": 13, "PTR": 14}
ALIAS_CHAIN = 8


def next_serial(current: int, today: date | None = None) -> int:
    """YYYYMMDDnn: today's first serial, or current + 1 if that is already higher."""
    base = int((today or datetime.now(timezone.utc).date()).strftime("%Y%m%d")) * 100
    return max(base, current + 1)


def _txt_rdata(text: str) -> str:
    """TXT text as zone-file character-strings: 255-byte chunks, quotes, backslashes and non-ASCII escaped."""
    raw = text.encode("utf-8")
    chunks = [raw[i : i + 255] for i in range(0, len(raw), 255)] or [b""]
    out = []
    for chunk in chunks:
        escaped = []
        for b in chunk:
            if b in (0x22, 0x5C):
                escaped.append("\\" + chr(b))
            elif 0x20 <= b < 0x7F:
                escaped.append(chr(b))
            else:
                escaped.append(f"\\{b:03d}")
        out.append('"' + "".join(escaped) + '"')
    return " ".join(out)


def rdata(record: Record) -> str:
    if record.type == "TXT":
        return _txt_rdata(record.value)
    if record.type in ("MX", "SRV"):
        return f"{record.priority} {record.value}"
    return record.value


def render_zone(zone: Zone, records: list[Record], serial: int, aliases: dict | None = None) -> str:
    """The zone file. ALIAS records become the A/AAAA records of `aliases` (default: the zone's last answers)."""
    aliases = (zone.alias_cache or {}) if aliases is None else aliases
    rows = sorted(
        (r for r in records if not r.disabled),
        key=lambda r: (r.name != "@", r.name.split(".")[::-1], TYPE_ORDER.get(r.type, 99), r.priority or 0, r.value),
    )
    lines = [
        "; Generated by DNSOne from MySQL. Do not edit: the next publish overwrites this file.",
        f"; zone {zone.name}, serial {serial}, revision {zone.revision}, generated {utcnow():%Y-%m-%d %H:%M:%S} UTC",
        f"$ORIGIN {zone.name}.",
        f"$TTL {zone.default_ttl}",
        f"@\tIN\tSOA\t{zone.soa_mname} {zone.soa_rname} (",
        f"\t\t{serial}\t; serial",
        f"\t\t{zone.soa_refresh}\t; refresh",
        f"\t\t{zone.soa_retry}\t; retry",
        f"\t\t{zone.soa_expire}\t; expire",
        f"\t\t{zone.soa_minimum} )\t; negative-cache TTL",
    ]
    for r in rows:
        ttl = "" if r.ttl is None else str(r.ttl)
        if r.type == "ALIAS":
            answer = aliases.get(r.value) or {}
            # The target's TTL caps the record's, so resolvers come back when the target may change.
            flat = str(min(r.ttl or zone.default_ttl, max(validation.MIN_TTL, int(answer.get("ttl") or zone.default_ttl))))
            lines.append(f"; ALIAS {r.name} -> {r.value}" + ("" if answer.get("A") or answer.get("AAAA") else " (no addresses)"))
            lines += [f"{r.name}\t{flat}\tIN\t{t}\t{a}" for t in ("A", "AAAA") for a in answer.get(t, [])]
            continue
        lines.append(f"{r.name}\t{ttl}\tIN\t{r.type}\t{rdata(r)}")
    return "\n".join(lines) + "\n"


def _hosted_answer(db: Session, target: str) -> dict | None:
    """A/AAAA of a target inside a hosted zone, from MySQL (following CNAMEs and ALIASes there), or None if not hosted."""
    names = db.scalars(select(Zone.name).where(Zone.status == "active")).all()
    seen = 0
    while seen < ALIAS_CHAIN:
        seen += 1
        fqdn = target.rstrip(".")
        zone_name = max((n for n in names if fqdn == n or fqdn.endswith(f".{n}")), key=len, default=None)
        if zone_name is None:
            return None if seen == 1 else {"chain": target}
        owner = "@" if fqdn == zone_name else fqdn[: -(len(zone_name) + 1)]
        rows = db.execute(select(Record.type, Record.value, Record.ttl, Zone.default_ttl).join(Zone, Zone.id == Record.zone_id).where(
            Zone.name == zone_name, Record.name == owner, Record.disabled.is_(False), Record.type.in_(("A", "AAAA", "CNAME", "ALIAS")))).all()
        follow = next((v for t, v, _, _ in rows if t in ("CNAME", "ALIAS")), None)
        if follow:
            target = follow
            continue
        ttls = [ttl or default for _, _, ttl, default in rows]
        return {"A": sorted(v for t, v, _, _ in rows if t == "A"), "AAAA": sorted(v for t, v, _, _ in rows if t == "AAAA"),
                "ttl": min(ttls) if ttls else validation.MIN_TTL, "source": "hosted"}
    return {"A": [], "AAAA": [], "ttl": validation.MIN_TTL, "source": "hosted", "error": "CNAME/ALIAS chain too long"}


def secondaries(db: Session) -> list[dict]:
    """Settings → Cluster: BIND secondaries ({"address", "port"}) the primary notifies."""
    row = db.get(Setting, "cluster.secondaries")
    return list(row.value.get("servers", [])) if row else []


def set_secondaries(db: Session, servers: list[dict]) -> list[dict]:
    out, seen = [], set()
    for i, server in enumerate(servers):
        try:
            address = str(validation.plain_ip(str(server.get("address", "")).strip()))
        except ValueError:
            raise validation.ValidationError(f"servers.{i}.address", "Enter the secondary's IP address.") from None
        port = int(server.get("port") or 5301)
        if not 1 <= port <= 65535:
            raise validation.ValidationError(f"servers.{i}.port", "Enter a port between 1 and 65535.")
        if address in seen:
            continue
        seen.add(address)
        out.append({"address": address, "port": port, "name": str(server.get("name") or "")[:64]})
    row = db.get(Setting, "cluster.secondaries")
    if row is None:
        db.add(Setting(name="cluster.secondaries", value={"servers": out}))
    else:
        row.value = {"servers": out}
    return out


def catalog_member_id(name: str, zone_id: int) -> str:
    """The catalog zone's unique label for a member zone: stable while the zone exists, new when a
    zone of the same name is created again (or restored), so secondaries drop their old copy."""
    return hashlib.sha1(f"{name}/{zone_id}".encode()).hexdigest()


def render_catalog(members: list[tuple[str, int]], serial: int) -> str:
    lines = [
        "; Generated by DNSOne: the zones this primary serves (RFC 9432 catalog, version 2). Do not edit.",
        "$TTL 3600",
        f"@\tIN\tSOA\tinvalid. invalid. {serial} 3600 600 2419200 3600",
        "@\tIN\tNS\tinvalid.",
        'version\tIN\tTXT\t"2"',
    ]
    lines += [f"{catalog_member_id(n, i)}.zones\tIN\tPTR\t{n}." for n, i in members]
    return "\n".join(lines) + "\n"


def _resolver(s: Settings) -> dns.resolver.Resolver:
    if s.alias_resolvers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = list(s.alias_resolvers)
    else:
        resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0
    resolver.timeout = 2.0
    return resolver


def resolve_aliases(db: Session, zone: Zone, records: list[Record], settings: Settings | None = None) -> tuple[dict, list[str]]:
    """The A/AAAA answers of the zone's ALIAS targets, and warnings. Unresolvable targets keep the cached answer."""
    s = settings or get_settings()
    targets = sorted({r.value for r in records if r.type == "ALIAS" and not r.disabled})
    cache = zone.alias_cache or {}
    out, warnings = {}, []
    resolver = None
    for target in targets:
        answer = _hosted_answer(db, target)
        if answer is not None and "chain" in answer:
            target_outside = answer["chain"]
            answer = None
        else:
            target_outside = target
        if answer is None:
            resolver = resolver or _resolver(s)
            answer, failed = {"A": [], "AAAA": [], "ttl": None, "source": "dns"}, None
            for rtype in ("A", "AAAA"):
                try:
                    result = resolver.resolve(target_outside, rtype, raise_on_no_answer=False)
                except dns.resolver.NXDOMAIN:
                    continue
                except (dns.exception.DNSException, OSError) as exc:
                    failed = exc.__class__.__name__
                    continue
                if result.rrset is not None:
                    answer[rtype] = sorted(r.address for r in result.rrset)
                    answer["ttl"] = min(answer["ttl"] or result.rrset.ttl, result.rrset.ttl)
            if failed and target in cache:
                warnings.append(f"ALIAS target {target} could not be resolved ({failed}); its last addresses are kept")
                out[target] = cache[target]
                continue
            if failed:
                warnings.append(f"ALIAS target {target} could not be resolved ({failed})")
        if not answer.get("A") and not answer.get("AAAA"):
            warnings.append(f"ALIAS target {target} has no A or AAAA records")
        answer["ttl"] = int(answer.get("ttl") or zone.default_ttl)
        out[target] = {k: answer[k] for k in ("A", "AAAA", "ttl")}
    return out, warnings


def _same_aliases(a: dict, b: dict) -> bool:
    """Equal addresses; TTL changes alone do not republish a zone."""
    strip = lambda d: {t: (v.get("A", []), v.get("AAAA", [])) for t, v in (d or {}).items()}
    return strip(a) == strip(b)


@dataclass
class PublishResult:
    zone: str
    ok: bool
    serial: int | None = None
    message: str = ""
    skipped: bool = False


class Publisher:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()

    # ------------------------------------------------------------------ paths and commands

    def zone_path(self, name: str) -> Path:
        return self.s.zones_dir / f"{name}.zone"

    def _rndc(self, *args: str) -> tuple[int, str]:
        cmd = [self.s.rndc, "-k", str(self.s.rndc_key), "-s", self.s.rndc_server, "-p", str(self.s.rndc_port), *args]
        return run(cmd, timeout=self.s.command_timeout)

    def checkzone(self, name: str, path: Path) -> tuple[bool, str]:
        cmd = [self.s.named_checkzone, "-k", "fail", "-n", "fail", "-m", "fail", "-M", "fail", "-S", "fail", "-i", "local", name, str(path)]
        code, out = run(cmd, timeout=self.s.command_timeout)
        return code == 0, out

    def bind_serial(self, name: str) -> int | None:
        """The SOA serial BIND is serving for the zone, or None if it does not answer for it."""
        return self._soa_serial(self.s.bind_address, self.s.bind_port, name)

    @staticmethod
    def _soa_serial(address: str, port: int, name: str) -> int | None:
        query = dns.message.make_query(f"{name}.", dns.rdatatype.SOA)
        query.flags &= ~0x0100  # no recursion desired: we ask the authoritative server
        try:
            response = dns.query.udp(query, address, port=port, timeout=2)
        except (dns.exception.DNSException, OSError):
            return None
        if not response.flags & 0x0400:  # AA bit: BIND answers with authority only for zones it loaded
            return None
        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                return int(rrset[0].serial)
        return None

    def wait_for_serial(self, name: str, serial: int, seconds: float = 8.0, or_later: bool = False) -> bool:
        """Waits until BIND serves `serial` (or, for a signed zone, a later one: BIND bumps it when signing)."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            served = self.bind_serial(name)
            if served == serial or (or_later and served is not None and 0 < (served - serial) % 2**32 < 2**31):
                return True
            time.sleep(0.2)
        return False

    # ------------------------------------------------------------------ server-wide include files

    def catalog_path(self) -> Path:
        # Not *.zone: the orphan clean-up in reconcile() leaves it alone.
        return self.s.zones_dir / f"{self.s.catalog_zone}.catalog"

    def _render_zones_conf(self, names: list[str], servers: list[dict] | None = None, signing: dict[str, str] | None = None,
                           xfr: dict[str, dict] | None = None) -> str:
        lines = [
            "// Generated by DNSOne from MySQL. Do not edit: the next publish overwrites this file.",
            "// Each zone is a primary; without secondaries (Settings → Cluster) or a zone's own transfer",
            "// settings (Zone → Transfers), transfers and notifies follow the options in named.conf.options.",
            "",
            dnssec_policy(self.s),
            "",
        ]
        signing = signing or {}
        xfr = xfr or {}
        keys = sorted({v["key"] for v in xfr.values() if v.get("key")})
        for kname, algorithm, secret in keys:
            lines.append(f'key "{kname}" {{ algorithm {algorithm}; secret "{secret}"; }};')
        if keys:
            lines.append("")
        transfer = []
        if servers:
            notify = " ".join(f"{s['address']} port {s['port']};" for s in servers)
            allow = " ".join(f"{s['address']};" for s in servers)
            transfer = ["    notify explicit;", f"    also-notify {{ {notify} }};", f"    allow-transfer {{ 127.0.0.1; {allow} }};"]
        for name in names:
            dnssec = []
            state = signing.get(name, "off")
            if state != "off":
                policy = '"dnsone"' if state == "on" else "insecure"
                dnssec = [f"    dnssec-policy {policy};", "    inline-signing yes;", f'    key-directory "{self.s.bind_key_dir}";']
            own = xfr.get(name)
            lines += [f'zone "{name}" {{', "    type primary;", f'    file "{self.zone_path(name)}";', *dnssec,
                      *(self._zone_transfer(own, servers or []) if own else transfer), "};"]
        if servers:
            lines += ["", "// Catalog of the zones above: secondaries add and remove zones from it.",
                      f'zone "{self.s.catalog_zone}" {{', "    type primary;", f'    file "{self.catalog_path()}";', *transfer, "};"]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _zone_transfer(own: dict, servers: list[dict]) -> list[str]:
        """allow-transfer and also-notify of a zone with its own transfer settings (transfers.py).

        dnsdist forwards customers' transfers from 127.0.0.1 after checking their address; with a key,
        BIND also wants the request signed with it, so unsigned ones from 127.0.0.1 are refused.
        """
        key = own.get("key")
        cluster = " ".join(f"{s['address']};" for s in servers)
        allow = f'key "{key[0]}"; !127.0.0.1; {cluster}' if key else f"127.0.0.1; {cluster}"
        signed = f' key "{key[0]}"' if key else ""
        targets = [f"{s['address']} port {s['port']};" for s in servers] + [f"{a} port {p}{signed};" for a, p in own.get("notify", [])]
        out = [f"    allow-transfer {{ {allow.strip()} }};"]
        if targets:
            out = ["    notify explicit;", f"    also-notify {{ {' '.join(targets)} }};", *out]
        return out

    def _sync_catalog(self, db: Session, names: list[str], servers: list[dict]) -> tuple[bool, bool, str]:
        """Writes the catalog zone when its members changed. Returns (ok, changed, message)."""
        path = self.catalog_path()
        if not servers:
            if path.exists():
                path.unlink()
            return True, False, ""
        row = db.get(Setting, "zonegen.catalog")
        state = dict(row.value) if row else {"serial": 0, "members": ""}
        ids = dict(db.execute(select(Zone.name, Zone.id).where(Zone.name.in_(names))).all()) if names else {}
        member_list = [(n, ids[n]) for n in names if n in ids]
        members = hashlib.sha1("\n".join(f"{n}/{i}" for n, i in member_list).encode()).hexdigest()
        if state.get("members") == members and path.exists():
            return True, False, ""
        # Above whatever a secondary already holds: the stored state can be gone (a new database, a
        # restore, secondaries removed and added again), and a lower serial would never be transferred.
        held = [self._soa_serial(srv["address"], srv["port"], self.s.catalog_zone) for srv in servers]
        serial = next_serial(max([int(state.get("serial") or 0), *(h for h in held if h is not None)]))
        tmp = write_temp(path, render_catalog(member_list, serial), 0o640)
        code, out = run([self.s.named_checkzone, "-i", "none", "-k", "ignore", self.s.catalog_zone, str(tmp)], timeout=self.s.command_timeout)
        if code != 0:
            tmp.unlink(missing_ok=True)
            return False, False, f"named-checkzone rejected the catalog zone: {out}"
        replace_keeping_previous(tmp, path)
        # Its own transaction: the caller may be in the middle of publishing a zone.
        own = new_session()
        try:
            stored = own.get(Setting, "zonegen.catalog")
            if stored is None:
                own.add(Setting(name="zonegen.catalog", value={"serial": serial, "members": members}))
            else:
                stored.value = {"serial": serial, "members": members}
            own.commit()
        finally:
            own.close()
        return True, True, f"catalog serial {serial} ({len(names)} zones)"

    def _configured_zones(self) -> set[str]:
        """Zones listed in the zones.conf BIND is running with."""
        conf = self.s.bind_zones_conf
        if not conf.exists():
            return set()
        return set(re.findall(r'^zone "([^"]+)" \{', conf.read_text(), flags=re.M))

    def _served_zones(self, db: Session) -> list[str]:
        """Active zones that have a validated file on disk."""
        names = db.scalars(select(Zone.name).where(Zone.status == "active", Zone.published_serial.is_not(None)).order_by(Zone.name)).all()
        return [n for n in names if self.zone_path(n).exists()]

    def sync_server_config(self, db: Session) -> tuple[bool, str]:
        """Rewrites zones.conf, forward-zones and the dnsdist list if the served set changed.

        Returns (ok, message). On a failed named-checkconf the previous zones.conf is restored.
        """
        if self.s.role == "replica":
            return self._sync_resolver_lists(db, self._replica_zones(db))
        names = self._served_zones(db)
        messages = []
        servers = secondaries(db)
        ok, catalog_changed, msg = self._sync_catalog(db, names, servers)
        if not ok:
            return False, msg

        signing = dict(db.execute(select(Zone.name, Zone.dnssec).where(Zone.dnssec != "off")).all())
        conf = self._render_zones_conf(names, servers, signing, transfers.server_view(db, names) if transfers else {})
        target = self.s.bind_zones_conf
        current = target.read_text() if target.exists() else None
        if conf == current and catalog_changed:
            code, out = self._rndc("reload", self.s.catalog_zone)
            messages.append(msg if code == 0 else f"warning: rndc reload {self.s.catalog_zone} failed: {out}")
        if conf != current:
            tmp = write_temp(target, conf, 0o640)
            previous = replace_keeping_previous(tmp, target)
            code, out = run([self.s.named_checkconf, str(self.s.named_conf)], timeout=self.s.command_timeout)
            if code != 0:
                restore_previous(target, previous)
                return False, f"named-checkconf rejected the generated zones.conf; previous file restored: {out}"
            code, out = self._rndc("reconfig")
            if code != 0:
                restore_previous(target, previous)
                self._rndc("reconfig")
                return False, f"rndc reconfig failed; previous zones.conf restored: {out}"
            messages.append(f"BIND now serves {len(names)} zone(s)")
            if catalog_changed and current is not None and f'zone "{self.s.catalog_zone}"' in current:
                # reconfig loads new zones but does not re-read the changed file of one it already serves.
                code, out = self._rndc("reload", self.s.catalog_zone)
                messages.append(msg if code == 0 else f"warning: rndc reload {self.s.catalog_zone} failed: {out}")

        ok, msg = self._sync_resolver_lists(db, names)
        return ok, "; ".join(m for m in messages + [msg] if m)

    def _replica_zones(self, db: Session) -> list[str]:
        """On a replica: the zones the primary has published (they arrive in BIND by transfer)."""
        return list(db.scalars(select(Zone.name).where(Zone.status == "active", Zone.published_serial.is_not(None)).order_by(Zone.name)))

    def _sync_resolver_lists(self, db: Session, names: list[str]) -> tuple[bool, str]:
        """Negative trust anchors, Recursor forward-zones and the dnsdist list for the served zones. A zone a reseller or
        customer created waits for an administrator's approval: until then the resolver answers it from the public DNS,
        so a tenant cannot take over someone else's domain for every subscriber."""
        approved = set(db.scalars(select(Zone.name).where(Zone.approved.is_(True))))
        names = [n for n in names if n in approved]
        messages = self._sync_ntas(names)

        forward = "".join(f"{n}={self.s.bind_address}:{self.s.bind_port}\n" for n in names)
        header = "# Generated by DNSOne: hosted zones are answered by the local BIND.\n"
        fz = self.s.recursor_forward_zones_file
        if not fz.exists() or fz.read_text() != header + forward:
            atomic_write(fz, header + forward, 0o644)
            code, out = run([*self.s.rec_control, "reload-zones"], timeout=self.s.command_timeout)
            if code != 0:
                messages.append(f"warning: rec_control reload-zones failed: {out}")
            else:
                messages.append("Recursor forward zones reloaded")

        auth = "".join(f"{n}\n" for n in names)
        af = self.s.dnsdist_auth_zones_file
        if not af.exists() or af.read_text() != auth:
            # dnsdist re-reads this file on its own (see dnsdist.conf maintenance()).
            atomic_write(af, auth, 0o644)
        return True, "; ".join(messages)

    NTA_BULK = 50

    def _sync_ntas(self, names: list[str]) -> list[str]:
        """Negative trust anchors for hosted zones.

        DNSOne does not sign zones, so a hosted zone the public DNS cannot vouch for (not delegated,
        a private TLD, or a stale DS at the parent) would validate as Bogus and clients asking for
        validation would get SERVFAIL. The local copy is authoritative for customers, so the
        Recursor skips validation for every hosted zone. recursor.lua loads the file at start; here
        the running Recursor is updated.
        """
        path = self.s.recursor_nta_file
        old = set(path.read_text().split()) if path.exists() else set()
        new = set(names)
        if old == new and path.exists():
            return []
        atomic_write(path, "".join(f"{n}\n" for n in sorted(new)), 0o644)
        added, removed = sorted(new - old), sorted(old - new)
        if len(added) + len(removed) > self.NTA_BULK:
            # Many changes at once (first start, restore): reload the Lua config, which reads the file.
            code, out = run([*self.s.rec_control, "reload-lua-config"], timeout=self.s.command_timeout)
            return [] if code == 0 else [f"warning: rec_control reload-lua-config failed: {out}"]
        for name in added:
            code, out = run([*self.s.rec_control, "add-nta", name, "DNSOne hosted zone"], timeout=self.s.command_timeout)
            if code != 0:
                return [f"warning: rec_control add-nta {name} failed: {out}"]
        if removed:
            code, out = run([*self.s.rec_control, "clear-nta", *removed], timeout=self.s.command_timeout)
            if code != 0:
                return [f"warning: rec_control clear-nta failed: {out}"]
        return []

    # ------------------------------------------------------------------ publishing

    def _lock(self) -> NamedLock:
        return NamedLock(f"dnsone:zonegen:{self.s.node_name}", timeout=120)

    def publish(self, zone_id: int, force: bool = False) -> PublishResult:
        if self.s.role == "replica":
            return PublishResult(zone=str(zone_id), ok=True, skipped=True, message="this node is a replica: the primary publishes")
        with self._lock():
            return self._publish_locked(zone_id, force)

    def _publish_locked(self, zone_id: int, force: bool) -> PublishResult:
        db = new_session()
        try:
            zone = db.get(Zone, zone_id)
            if zone is None:
                return PublishResult(zone=str(zone_id), ok=False, message="zone not found", skipped=True)
            if zone.status != "active":
                ok, msg = self.sync_server_config(db)
                if ok:
                    db.execute(update(Zone).where(Zone.id == zone.id, Zone.revision == zone.revision).values(publish_state="published", published_revision=zone.revision, last_error=None))
                    db.commit()
                return PublishResult(zone=zone.name, ok=ok, message=msg or "zone is disabled and not served", skipped=True)
            if not force and zone.revision == zone.published_revision and zone.publish_state == "published" and self.zone_path(zone.name).exists():
                return PublishResult(zone=zone.name, ok=True, serial=zone.published_serial, skipped=True, message="up to date")

            revision = zone.revision
            records = list(db.scalars(select(Record).where(Record.zone_id == zone.id)))
            floor = max(zone.serial, zone.published_serial or 0)
            if zone.dnssec != "off":
                # Above what BIND serves: it may have bumped the signed zone's serial past the file's.
                floor = max(floor, self.bind_serial(zone.name) or 0)
            serial = next_serial(floor)
            if zone.dnssec != "off":
                longest = max([zone.default_ttl, *(r.ttl for r in records if r.ttl is not None and not r.disabled)])
                if longest > self.s.dnssec_max_zone_ttl:
                    message = (f"The zone is signed and has a TTL of {longest} s; signed zones allow at most {self.s.dnssec_max_zone_ttl} s"
                               " (DNSONE_DNSSEC_MAX_ZONE_TTL). Lower the TTL; the live zone was not changed.")
                    db.execute(update(Zone).where(Zone.id == zone.id).values(publish_state="error", last_error=message))
                    db.commit()
                    return PublishResult(zone=zone.name, ok=False, message=message)
            aliases, warnings = resolve_aliases(db, zone, records, self.s) if any(r.type == "ALIAS" for r in records) else ({}, [])
            text = render_zone(zone, records, serial, aliases)
            result = self._write_and_load(db, zone, text, serial)
            if result.ok:
                # Only mark it published if nobody changed the zone while we were writing it.
                done = db.execute(
                    update(Zone)
                    .where(Zone.id == zone.id, Zone.revision == revision)
                    .values(serial=serial, published_serial=serial, published_revision=revision, published_at=utcnow(), publish_state="published", last_error=None)
                ).rowcount
                if not done:
                    db.execute(update(Zone).where(Zone.id == zone.id).values(serial=serial, published_serial=serial, published_at=utcnow()))
                    result.message = "published; newer changes are queued"
                db.execute(update(Zone).where(Zone.id == zone.id).values(alias_cache=aliases or None))
                if warnings:
                    result.message += "; " + "; ".join(warnings)
                if done:
                    history.record(db, zone, records, serial, revision)
            else:
                db.execute(update(Zone).where(Zone.id == zone.id).values(publish_state="error", last_error=result.message[:60000]))
            db.commit()
            log.info("publish %s: ok=%s serial=%s %s", zone.name, result.ok, result.serial, result.message)
            return result
        finally:
            db.close()

    def _write_and_load(self, db: Session, zone: Zone, text: str, serial: int) -> PublishResult:
        target = self.zone_path(zone.name)
        tmp = write_temp(target, text, 0o640)
        try:
            ok, out = self.checkzone(zone.name, tmp)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        if not ok:
            tmp.unlink(missing_ok=True)
            return PublishResult(zone=zone.name, ok=False, message=f"named-checkzone rejected the zone; the live file was not changed.\n{out}")

        known = zone.name in self._configured_zones()
        previous = replace_keeping_previous(tmp, target)
        if not known:
            # BIND does not know the zone yet: list it in zones.conf and reconfigure.
            db.execute(update(Zone).where(Zone.id == zone.id).values(published_serial=serial))
            db.flush()
            ok, msg = self.sync_server_config(db)
            if not ok:
                restore_previous(target, previous)
                db.execute(update(Zone).where(Zone.id == zone.id).values(published_serial=zone.published_serial))
                return PublishResult(zone=zone.name, ok=False, message=msg)
        else:
            # Signing turned on or off changes the zone's statement in zones.conf (a no-op otherwise).
            ok, msg = self.sync_server_config(db)
            if not ok:
                restore_previous(target, previous)
                return PublishResult(zone=zone.name, ok=False, message=msg)
            code, out = self._rndc("reload", zone.name)
            if code != 0:
                restore_previous(target, previous)
                self._rndc("reload", zone.name)
                return PublishResult(zone=zone.name, ok=False, message=f"rndc reload failed; previous file restored.\n{out}")

        if not self.wait_for_serial(zone.name, serial, seconds=15.0 if zone.dnssec != "off" else 8.0, or_later=zone.dnssec != "off"):
            restore_previous(target, previous)
            served = self.bind_serial(zone.name)
            if known:
                self._rndc("reload", zone.name)
            else:
                db.execute(update(Zone).where(Zone.id == zone.id).values(published_serial=zone.published_serial))
                db.flush()
                self.sync_server_config(db)
            return PublishResult(zone=zone.name, ok=False, message=f"BIND did not load serial {serial} (it serves {served}); previous file restored. Check `journalctl -u named`.")
        # Clients resolve hosted zones through the Recursor: drop its cached copy so they see the change now.
        code, out = run([*self.s.rec_control, "wipe-cache", f"{zone.name}$"], timeout=self.s.command_timeout)
        if code != 0:
            log.warning("rec_control wipe-cache %s failed: %s", zone.name, out)
        return PublishResult(zone=zone.name, ok=True, serial=serial, message=f"published serial {serial}")

    def remove(self, name: str) -> PublishResult:
        """Stops serving a deleted zone and removes its files."""
        if self.s.role == "replica":
            return PublishResult(zone=name, ok=True, skipped=True, message="this node is a replica: the primary publishes")
        with self._lock():
            db = new_session()
            try:
                ok, msg = self.sync_server_config(db)
            finally:
                db.close()
            if ok:
                for suffix in ZONE_FILE_SUFFIXES:
                    self.s.zones_dir.joinpath(f"{name}{suffix}").unlink(missing_ok=True)
                fsync_dir(self.s.zones_dir)
            return PublishResult(zone=name, ok=ok, message=msg or "removed")

    def reconcile(self, force: bool = False) -> list[PublishResult]:
        """Publishes every zone whose files are behind MySQL, then aligns the include files.

        Run by dnsone-reconcile.timer; also safe to run by hand (`dnsone-ctl zones reconcile`).
        """
        results: list[PublishResult] = []
        if self.s.role == "replica":
            ok, msg = self.replica_sync()
            return [PublishResult(zone="(replica)", ok=ok, message=msg, skipped=ok)]
        with self._lock():
            db = new_session()
            try:
                zones = list(db.scalars(select(Zone).order_by(Zone.name)))
            finally:
                db.close()
            with_alias, versioned = self._alias_zones(), self._versioned_zones()
            for zone in zones:
                needs = force or zone.revision != zone.published_revision or zone.publish_state != "published"
                if zone.status == "active" and not self.zone_path(zone.name).exists():
                    needs = True
                if not needs and zone.status == "active" and zone.id in with_alias:
                    needs = self._aliases_moved(zone)
                if not needs and zone.id not in versioned:
                    # Zones published before 1.4 (or a restore): their current state becomes the first version.
                    self._baseline(zone)
                if needs:
                    try:
                        results.append(self._publish_locked(zone.id, force=True))
                    except (CommandError, OSError) as exc:
                        results.append(PublishResult(zone=zone.name, ok=False, message=str(exc)))
            db = new_session()
            try:
                ok, msg = self.sync_server_config(db)
                known = set(db.scalars(select(Zone.name)).all())
            finally:
                db.close()
            if not ok:
                results.append(PublishResult(zone="(zones.conf)", ok=False, message=msg))
            # DNSSEC: hosted parents' DS records, and BIND told when the parent's DS changed (dnssec.py).
            db = new_session()
            try:
                for m in dnssec.sync(db, lambda zone_id: self._publish_locked(zone_id, False), self.s):
                    results.append(PublishResult(zone="(dnssec)", ok="failed" not in m, message=m))
            finally:
                db.close()
            # Files of zones that no longer exist in MySQL.
            if self.s.zones_dir.exists():
                for path in self.s.zones_dir.iterdir():
                    if path.name.startswith(".") and path.name.endswith(".tmp"):
                        if time.time() - path.stat().st_mtime > 3600:
                            path.unlink(missing_ok=True)
                        continue
                    stem = next((path.name[: -len(sfx)] for sfx in ZONE_FILE_SUFFIXES if path.name.endswith(sfx)), None)
                    if stem is not None and stem not in known:
                        log.info("removing orphan zone file %s", path)
                        path.unlink(missing_ok=True)
        return results


    def _alias_zones(self) -> set[int]:
        db = new_session()
        try:
            return set(db.scalars(select(Record.zone_id).where(Record.type == "ALIAS", Record.disabled.is_(False)).distinct()))
        finally:
            db.close()

    def _versioned_zones(self) -> set[int]:
        db = new_session()
        try:
            return history.zones_with_versions(db)
        finally:
            db.close()

    def _aliases_moved(self, zone: Zone) -> bool:
        """True when an ALIAS target now resolves to other addresses than the published ones."""
        db = new_session()
        try:
            records = list(db.scalars(select(Record).where(Record.zone_id == zone.id, Record.type == "ALIAS")))
            fresh, _ = resolve_aliases(db, zone, records, self.s)
        finally:
            db.close()
        moved = not _same_aliases(fresh, zone.alias_cache or {})
        if moved:
            log.info("ALIAS targets of %s changed; republishing", zone.name)
        return moved

    def _baseline(self, zone: Zone) -> None:
        if zone.published_serial is None:
            return
        db = new_session()
        try:
            records = list(db.scalars(select(Record).where(Record.zone_id == zone.id)))
            history.record(db, zone, records, zone.published_serial, zone.published_revision)
            db.commit()
        finally:
            db.close()

    def replica_sync(self) -> tuple[bool, str]:
        """On a replica: align the resolver lists, and wipe the Recursor's cache of zones that changed.

        A zone's cache is wiped once the local BIND secondary serves the serial MySQL says was
        published, so clients never see the old data cached again after the transfer.
        """
        with self._lock():
            db = new_session()
            try:
                ok, msg = self.sync_server_config(db)
                published = dict(db.execute(select(Zone.name, Zone.published_serial).where(Zone.status == "active", Zone.published_serial.is_not(None))).all())
            finally:
                db.close()
        state_path = self.s.recursor_forward_zones_file.with_name("zone-serials.json")
        try:
            seen = json.loads(state_path.read_text())
        except (OSError, ValueError):
            seen = {}
        wiped, waiting = [], 0
        for name, serial in published.items():
            if seen.get(name) == serial:
                continue
            if self.bind_serial(name) != serial:
                waiting += 1
                continue
            if name in seen:
                run([*self.s.rec_control, "wipe-cache", f"{name}$"], timeout=self.s.command_timeout)
                wiped.append(name)
            seen[name] = serial
        seen = {k: v for k, v in seen.items() if k in published}
        atomic_write(state_path, json.dumps(seen, sort_keys=True), 0o644)
        parts = [msg] if msg else []
        if wiped:
            parts.append(f"cache wiped for {len(wiped)} updated zone(s)")
        if waiting:
            parts.append(f"{waiting} zone(s) not transferred yet")
        return ok, "; ".join(parts)


def publish_in_background(zone_id: int) -> None:
    """FastAPI background task: publish one zone after the request committed. Errors land on the zone row."""
    try:
        Publisher().publish(zone_id)
    except Exception:  # noqa: BLE001 - logged; the reconcile timer retries
        log.exception("background publish of zone %s failed", zone_id)
        db = new_session()
        try:
            db.execute(update(Zone).where(Zone.id == zone_id).values(publish_state="error", last_error="Publishing failed with an internal error; see the DNSOne log. The reconcile job retries every 5 minutes."))
            db.commit()
        finally:
            db.close()


def remove_in_background(name: str) -> None:
    try:
        Publisher().remove(name)
    except Exception:  # noqa: BLE001
        log.exception("removing zone %s from BIND failed", name)
