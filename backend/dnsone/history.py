"""Zone history: a version of the zone for every publish that changed it, to compare and roll back to.

A version holds the zone's settings (TTL, SOA timers and names, description) and every record, as
compressed JSON (zone_versions.snapshot), with what changed since the version before and who changed
it (from the audit log). The zone generator records one after each successful publish, so versions are
what was live, and several edits published together make one version. The reconcile timer gives zones
without any version (published before 1.4, restored from a backup) their current state as the first.

Rolling back replaces the zone's settings and records with a version's, as one new change that is
audited and published like any other (and so becomes the newest version). Status, DNSSEC signing and
dynamic DNS keys are not part of a version and are left as they are.
"""

from __future__ import annotations

import hashlib
import json
import zlib
from datetime import datetime

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session

from .models import AuditLog, Record, Zone, ZoneVersion

KEEP = 100
SETTINGS = ("description", "default_ttl", "soa_mname", "soa_rname", "soa_refresh", "soa_retry", "soa_expire", "soa_minimum")
RECORD_FIELDS = ("name", "type", "value", "ttl", "priority", "disabled", "comment")


def snapshot(zone: Zone, records: list[Record]) -> dict:
    rows = sorted(({f: getattr(r, f) for f in RECORD_FIELDS} for r in records),
                  key=lambda r: (r["name"] != "@", r["name"], r["type"], r["priority"] or 0, r["value"]))
    for r in rows:
        r["disabled"] = bool(r["disabled"])
    return {"zone": {f: getattr(zone, f) for f in SETTINGS}, "records": rows}


def _encode(data: dict) -> tuple[bytes, str]:
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return zlib.compress(raw, 6), hashlib.sha1(raw).hexdigest()


def load(version: ZoneVersion) -> dict:
    return json.loads(zlib.decompress(version.snapshot))


def _key(r: dict) -> tuple:
    return (r["name"], r["type"], r["priority"], r["value"])


def diff(old: dict | None, new: dict) -> dict:
    """What turns `old` into `new`: records added, removed and changed (TTL, comment, disabled), settings changed."""
    before = {_key(r): r for r in (old or {}).get("records", [])}
    after = {_key(r): r for r in new["records"]}
    added = [after[k] for k in after if k not in before]
    removed = [before[k] for k in before if k not in after]
    changed = [{"from": before[k], "to": after[k]} for k in after if k in before and before[k] != after[k]]
    settings = [{"field": f, "from": (old or {}).get("zone", {}).get(f), "to": new["zone"].get(f)}
                for f in SETTINGS if old is not None and old["zone"].get(f) != new["zone"].get(f)]
    return {"added": added, "removed": removed, "changed": changed, "settings": settings}


def summary(d: dict) -> dict:
    return {"added": len(d["added"]), "removed": len(d["removed"]), "changed": len(d["changed"]), "settings": [s["field"] for s in d["settings"]]}


def _actors(db: Session, zone: Zone, since: datetime | None) -> list[str]:
    """Who changed the zone since the previous version (zone and record entries in the audit log)."""
    stmt = select(AuditLog.actor).where(or_(
        and_(AuditLog.entity == "zone", AuditLog.entity_id == str(zone.id)),
        and_(AuditLog.entity == "record", func.json_unquote(func.json_extract(AuditLog.payload_json, "$.zone")) == zone.name),
    ), AuditLog.action.not_in(("zone.publish_requested",)))
    if since is not None:
        stmt = stmt.where(AuditLog.created_at > since)
    return sorted(set(db.scalars(stmt.distinct()).all()))[:20]


def record(db: Session, zone: Zone, records: list[Record], serial: int, revision: int) -> ZoneVersion | None:
    """Stores the published state as a new version unless it equals the latest one. The caller commits."""
    data = snapshot(zone, records)
    blob, digest = _encode(data)
    latest = db.scalar(select(ZoneVersion).where(ZoneVersion.zone_id == zone.id).order_by(ZoneVersion.id.desc()).limit(1))
    if latest is not None and latest.digest == digest:
        return None
    changes = summary(diff(load(latest) if latest else None, data)) if latest else {"added": len(data["records"]), "removed": 0, "changed": 0, "settings": [], "first": True}
    version = ZoneVersion(zone_id=zone.id, serial=serial, revision=revision, record_count=len(data["records"]), digest=digest, snapshot=blob,
                          changes=changes, actors=_actors(db, zone, latest.created_at if latest else None))
    db.add(version)
    db.flush()
    old = db.scalars(select(ZoneVersion.id).where(ZoneVersion.zone_id == zone.id).order_by(ZoneVersion.id.desc()).offset(KEEP)).all()
    if old:
        db.execute(delete(ZoneVersion).where(ZoneVersion.id.in_(old)))
    return version


def zones_with_versions(db: Session) -> set[int]:
    return set(db.scalars(select(ZoneVersion.zone_id).distinct()))


def current(db: Session, zone: Zone) -> dict:
    return snapshot(zone, list(db.scalars(select(Record).where(Record.zone_id == zone.id))))
