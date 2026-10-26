"""DNSSEC of hosted zones: their status, and keeping BIND and the parent's DS records in step.

BIND signs the zones (see zonegen); DNSOne reads what BIND serves: the DNSKEY, CDS and CDNSKEY sets
from the local BIND, the DS set the parent zone publishes (through the system resolver, or from MySQL
when the parent is hosted here too), and `rndc dnssec -status`.

BIND moves a key's DS through hidden, rumoured and omnipresent only when told the parent publishes
(or withdrew) it. sync() (dnsone-ctl zones reconcile, every 5 minutes) tells it with
`rndc dnssec -checkds` once the parent shows the change, so signing finishes, and key rollovers
(`rndc dnssec -rollover`) complete, without an operator watching. BIND publishes CDS and CDNSKEY for
the key the parent should point to, which registries that scan for them (RFC 8078) pick up by
themselves. When the parent zone is hosted here too, DNSOne is that registry: it copies the child's
CDS set into the parent's DS records (and removes them when signing is turned off).
"""

from __future__ import annotations

import logging
import re

import dns.dnssec
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from . import validation
from .config import Settings, get_settings
from .models import Record, Setting, Zone
from .system import run

log = logging.getLogger(__name__)
# Comment on DS records DNSOne keeps in a hosted parent zone.
MANAGED_COMMENT = "DNSSEC: kept in step with the child zone's CDS by DNSOne"

SEP = 0x0001  # DNSKEY flag: secure entry point (the key the parent's DS points to)


def _query_bind(s: Settings, name: str, rdtype) -> list:
    query = dns.message.make_query(f"{name}.", rdtype, want_dnssec=True)
    query.flags &= ~0x0100
    try:
        response = dns.query.udp(query, s.bind_address, port=s.bind_port, timeout=2)
        if response.flags & 0x0200:  # truncated: DNSKEY sets with signatures can exceed UDP
            response = dns.query.tcp(query, s.bind_address, port=s.bind_port, timeout=3)
    except (dns.exception.DNSException, OSError):
        return []
    return [rd for rrset in response.answer if rrset.rdtype == rdtype for rd in rrset]


def parent_ds(name: str) -> list[str] | None:
    """The DS records the public DNS has for the zone (None: could not ask)."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    try:
        return sorted(rd.to_text().lower() for rd in resolver.resolve(f"{name}.", "DS", raise_on_no_answer=False) or [])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except (dns.exception.DNSException, OSError):
        return None


def _rndc(s: Settings, *args: str) -> tuple[int, str]:
    return run([s.rndc, "-k", str(s.rndc_key), "-s", s.rndc_server, "-p", str(s.rndc_port), *args], timeout=10)


KEY_LINE = re.compile(r"^key: (\d+) \(([^)]+)\), (CSK|KSK|ZSK)\s*$")
STATE_LINE = re.compile(r"^\s*- (goal|dnskey|ds|zone rrsig|key rrsig):\s+(\w+)")


def key_states(status: str) -> list[dict]:
    """The keys in `rndc dnssec -status` output: [{tag, algorithm, role, goal, dnskey, ds, ...}]."""
    keys: list[dict] = []
    for line in status.splitlines():
        m = KEY_LINE.match(line.strip())
        if m:
            keys.append({"tag": int(m.group(1)), "algorithm": m.group(2), "role": m.group(3)})
            continue
        m = STATE_LINE.match(line)
        if m and keys:
            keys[-1][m.group(1).replace(" ", "_")] = m.group(2)
        elif keys and line.strip() and ":" not in line.strip()[:2]:
            keys[-1].setdefault("notes", []).append(line.strip())
    return keys


STATES = ("dnskey", "ds", "zone_rrsig", "key_rrsig")


def in_progress(keys: list[dict]) -> bool:
    """A key is still coming in (its DNSKEY or DS not everywhere yet) or going out (not gone everywhere)."""
    for k in keys:
        if k["role"] not in ("CSK", "KSK"):
            continue
        if k.get("goal") == "hidden" and any(k.get(f) not in (None, "hidden") for f in STATES):
            return True
        if k.get("goal") == "omnipresent" and (k.get("dnskey") != "omnipresent" or k.get("ds") != "omnipresent"):
            return True
    return False


def cds(name: str, settings: Settings | None = None) -> list[str]:
    """The CDS set BIND publishes for the zone (DS text form, lower-case); ['0 0 0 00'] means "remove the DS"."""
    s = settings or get_settings()
    return sorted(rd.to_text().lower() for rd in _query_bind(s, name, dns.rdatatype.CDS))


def _ds_of(name: str, key) -> str:
    return dns.dnssec.make_ds(dns.name.from_text(f"{name}."), key, "SHA256").to_text().lower()


def hosted_parent(db: Session, name: str) -> Zone | None:
    """The closest enclosing zone hosted here (active), if any: DNSOne then manages the zone's DS records in it."""
    labels = name.split(".")
    candidates = [".".join(labels[i:]) for i in range(1, len(labels))]
    if not candidates:
        return None
    zones = {z.name: z for z in db.scalars(select(Zone).where(Zone.name.in_(candidates), Zone.status == "active"))}
    return next((zones[c] for c in candidates if c in zones), None)


def _hosted_ds(db: Session, parent: Zone, name: str) -> list[str]:
    owner = name[: -(len(parent.name) + 1)]
    return sorted(v.lower() for v in db.scalars(select(Record.value).where(Record.zone_id == parent.id, Record.name == owner,
                                                                              Record.type == "DS", Record.disabled.is_(False))))


def describe(name: str, state: str, settings: Settings | None = None, db: Session | None = None) -> dict:
    s = settings or get_settings()
    keys = _query_bind(s, name, dns.rdatatype.DNSKEY) if state != "off" else []
    entry = [k for k in keys if k.flags & SEP]
    ds = [_ds_of(name, k) for k in entry]
    parent_zone = hosted_parent(db, name) if db is not None else None
    if state == "off":
        parent = None
    elif parent_zone is not None:
        parent = _hosted_ds(db, parent_zone, name)
    else:
        parent = parent_ds(name)
    status = ""
    if state != "off":
        code, out = _rndc(s, "dnssec", "-status", name)
        status = out.strip() if code == 0 else f"rndc dnssec -status failed: {out.strip()[:500]}"
    if state == "off":
        summary = "not signed"
    elif state == "insecure":
        summary = "signing is being removed: delete the DS records at the registrar" if parent else "signing removed"
    elif not keys:
        summary = "signing: BIND is creating the keys (this takes a few seconds after the publish)"
    elif parent is None:
        summary = "signed; the parent's DS records could not be checked"
    elif set(ds) & set(parent):
        summary = "signed and secure: the parent publishes a matching DS record"
    elif parent:
        summary = "signed, but the DS records at the parent do not match these keys: update them at the registrar"
    else:
        summary = "signed; give the DS record below to the registrar to make the zone secure"
    states = {k["tag"]: k for k in key_states(status)}
    published_cds = cds(name, s) if state != "off" else []
    rolling = in_progress(list(states.values()))
    return {
        "summary": summary,
        "keys": [{"tag": dns.dnssec.key_id(k), "flags": k.flags, "algorithm": dns.dnssec.algorithm_to_text(k.algorithm),
                  "dnskey": k.to_text(), **{f: states.get(dns.dnssec.key_id(k), {}).get(f) for f in ("role", "goal", "dnskey", "ds")},
                  "ds_record": _ds_of(name, k) if k.flags & SEP else None} for k in keys],
        "ds": ds,
        "cds": published_cds,
        "parent_ds": parent,
        "parent_zone": parent_zone.name if parent_zone is not None else None,
        "secure": bool(parent) and bool(set(ds) & set(parent or [])),
        "rolling": rolling,
        "bind_status": status,
    }


# --------------------------------------------------------------------------- keeping BIND and the parent in step


def _sync_hosted_parent(db: Session, zone: Zone, parent: Zone, s: Settings) -> str | None:
    """Makes the parent zone's DS records for `zone` what the child asks for (its CDS set). Returns what changed."""
    if zone.dnssec == "insecure" or (zone.dnssec == "on" and zone.status != "active"):
        wanted: list[str] | None = []
    else:
        published = cds(zone.name, s)
        if not published:
            # BIND publishes CDS once the new key reached every resolver: until then, leave the parent alone.
            return None
        wanted = [] if published == ["0 0 0 00"] else published
    owner = zone.name[: -(len(parent.name) + 1)]
    if not db.scalar(select(Record.id).where(Record.zone_id == parent.id, Record.name == owner, Record.type == "NS").limit(1)):
        # Not delegated from the parent (no NS records there): a DS record cannot go there.
        return None
    canonical = [validation.record(parent.name, owner, "DS", value, None)[2] for value in wanted]
    if sorted(v.lower() for v in canonical) == _hosted_ds(db, parent, zone.name):
        return None
    db.execute(delete(Record).where(Record.zone_id == parent.id, Record.name == owner, Record.type == "DS"))
    for value in canonical:
        db.add(Record(zone_id=parent.id, name=owner, type="DS", value=value, comment=MANAGED_COMMENT))
    db.execute(update(Zone).where(Zone.id == parent.id).values(revision=Zone.revision + 1, publish_state="pending"))
    return f"{parent.name}: DS records of {zone.name} set to {len(canonical)} record(s) from its CDS"


def sync_zone(db: Session, zone: Zone, publish, settings: Settings | None = None) -> list[str]:
    """One signed zone: the hosted parent's DS records, then BIND told what the parent publishes. Returns what it did.

    publish(zone_id) publishes a changed parent zone: Publisher.publish, or its locked variant when the
    caller already holds the zone generator's lock (reconcile).
    """
    s = settings or get_settings()
    done: list[str] = []
    parent_zone = hosted_parent(db, zone.name)
    if parent_zone is not None:
        msg = _sync_hosted_parent(db, zone, parent_zone, s)
        if msg:
            done.append(msg)
            db.commit()
            # The parent publishes now; the next check sees the DS there and tells BIND.
            result = publish(parent_zone.id)
            if not result.ok:
                done.append(f"publishing {parent_zone.name} failed: {result.message}")
            return done
    code, status = _rndc(s, "dnssec", "-status", zone.name)
    if code != 0:
        return [f"rndc dnssec -status {zone.name} failed: {status.strip()[:200]}"]
    states = key_states(status)
    keys = {dns.dnssec.key_id(k): k for k in _query_bind(s, zone.name, dns.rdatatype.DNSKEY) if k.flags & SEP}
    parent = _hosted_ds(db, parent_zone, zone.name) if parent_zone is not None else parent_ds(zone.name)
    if parent is None:
        return done
    told = _told(db)
    for key in states:
        if key["role"] not in ("CSK", "KSK") or key["tag"] not in keys:
            continue
        in_parent = _ds_of(zone.name, keys[key["tag"]]) in parent
        if key.get("goal") == "omnipresent" and key.get("ds") in ("hidden", "rumoured") and in_parent:
            what = "published"
        elif key.get("goal") == "hidden" and key.get("ds") in ("omnipresent", "unretentive") and not in_parent:
            what = "withdrawn"
        else:
            continue
        # Once per key and direction: BIND counts the parent's TTL from the moment it is told, and
        # telling it again would restart that wait.
        mark = f"{zone.name}/{key['tag']}"
        if told.get(mark) == what:
            continue
        code, out = _rndc(s, "dnssec", "-checkds", "-key", str(key["tag"]), what, zone.name)
        if code == 0:
            told[mark] = what
            _store_told(db, told)
        done.append(f"{zone.name}: key {key['tag']} DS {what} at the parent" + ("" if code == 0 else f" (rndc failed: {out.strip()[:200]})"))
    return done


TOLD_KEY = "dnssec.checkds"


def _told(db: Session) -> dict:
    row = db.get(Setting, TOLD_KEY)
    return dict(row.value) if row else {}


def _store_told(db: Session, told: dict) -> None:
    row = db.get(Setting, TOLD_KEY)
    if row is None:
        db.add(Setting(name=TOLD_KEY, value=told))
    else:
        row.value = told
    db.commit()


def sync(db: Session, publish, settings: Settings | None = None) -> list[str]:
    """Every zone that is signed or being unsigned (dnsone-ctl zones reconcile)."""
    s = settings or get_settings()
    out: list[str] = []
    zones = db.scalars(select(Zone).where(Zone.dnssec != "off", Zone.published_serial.is_not(None)).order_by(Zone.name)).all()
    for zone in zones:
        try:
            out += sync_zone(db, zone, publish, s)
        except (dns.exception.DNSException, OSError, validation.ValidationError) as exc:
            out.append(f"{zone.name}: DNSSEC check failed: {exc}")
    # Forget what BIND was told about zones no longer signed (a zone signed again gets new keys).
    told = _told(db)
    names = {z.name for z in zones}
    kept = {k: v for k, v in told.items() if k.rsplit("/", 1)[0] in names}
    if kept != told:
        _store_told(db, kept)
    for m in out:
        log.info("dnssec: %s", m)
    return out


def rollover(name: str, settings: Settings | None = None) -> tuple[bool, str]:
    """Starts a rollover of the zone's signing key: a new key is introduced, and the old one retired once
    the parent publishes the new DS (sync() notices)."""
    s = settings or get_settings()
    code, status = _rndc(s, "dnssec", "-status", name)
    if code != 0:
        return False, f"rndc dnssec -status failed: {status.strip()[:300]}"
    keys = key_states(status)
    active = [k for k in keys if k["role"] in ("CSK", "KSK") and k.get("goal") == "omnipresent"]
    if len(active) != 1 or in_progress(keys):
        return False, ("The signing key is not settled yet: a rollover is under way, or the parent does not publish its DS record yet."
                       " Roll the key once the DS is at the parent and the previous key is gone.")
    code, out = _rndc(s, "dnssec", "-rollover", "-key", str(active[0]["tag"]), name)
    if code != 0:
        return False, f"rndc dnssec -rollover failed: {out.strip()[:300]}"
    return True, (f"Rolling key {active[0]['tag']}: BIND introduces a new key now and publishes its CDS once it has reached every resolver;"
                  " the old key's DS goes once the new one is at the parent, and the old key itself once BIND has re-signed the zone.")
