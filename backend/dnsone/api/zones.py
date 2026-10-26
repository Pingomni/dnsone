"""Zones and records.

Every write bumps the zone's revision and marks it `pending` in the same transaction; after the
commit a background task publishes it (zonegen), and the reconcile timer retries anything left
behind. The zone row is locked (SELECT ... FOR UPDATE) during record writes, so concurrent edits
of one zone cannot slip past the CNAME and apex-NS checks.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, insert, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, dnssec, history, quota, templates, validation, zoneio
from ..db import get_db
from ..models import Record, Zone, ZoneVersion, user_zones
from ..security import iso
from ..zonegen import Publisher, next_serial, publish_in_background, remove_in_background, render_zone
from .deps import Actor, ApiError, Paging, field_error, like, not_found, quota_error, require

router = APIRouter(prefix="/api/zones", tags=["zones"])

# --------------------------------------------------------------------------- schemas


class NameServer(BaseModel):
    host: str = Field(max_length=253)
    address: str | None = Field(default=None, max_length=45)


class ZoneCreate(BaseModel):
    name: str = Field(max_length=253)
    description: str = Field(default="", max_length=255)
    default_ttl: int = 3600
    soa_rname: str = Field(max_length=253)
    nameservers: list[NameServer] = Field(min_length=1, max_length=10)
    # A zone template whose records the zone starts with, and its variables' values.
    template_id: int | None = None
    variables: dict[str, str] = Field(default_factory=dict)


class TemplateApply(BaseModel):
    template_id: int
    variables: dict[str, str] = Field(default_factory=dict)
    dry_run: bool = False


class ZoneUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=255)
    default_ttl: int | None = None
    soa_mname: str | None = Field(default=None, max_length=253)
    soa_rname: str | None = Field(default=None, max_length=253)
    soa_refresh: int | None = None
    soa_retry: int | None = None
    soa_expire: int | None = None
    soa_minimum: int | None = None
    status: Literal["active", "disabled"] | None = None
    # True: BIND signs the zone. False: signing is removed (the zone goes through dnssec-policy insecure).
    dnssec: bool | None = None


class RecordIn(BaseModel):
    name: str = Field(default="@", max_length=253)
    type: str = Field(max_length=5)
    value: str = Field(default="", max_length=4096)
    ttl: int | None = None
    priority: int | None = None
    disabled: bool = False
    comment: str = Field(default="", max_length=255)


class RecordPatch(BaseModel):
    name: str | None = Field(default=None, max_length=253)
    type: str | None = Field(default=None, max_length=5)
    value: str | None = Field(default=None, max_length=4096)
    ttl: int | None = None
    clear_ttl: bool = False
    priority: int | None = None
    disabled: bool | None = None
    comment: str | None = Field(default=None, max_length=255)


class AxfrSource(BaseModel):
    server: str = Field(max_length=45)
    port: int = 53
    tsig_name: str = Field(default="", max_length=253)
    tsig_secret: str = Field(default="", max_length=512)
    tsig_algorithm: str = Field(default="hmac-sha256", max_length=16)


class ImportSource(BaseModel):
    """A zone file (text) or a zone transfer from another server (axfr): exactly one."""
    text: str | None = Field(default=None, max_length=20_000_000)
    axfr: AxfrSource | None = None
    dry_run: bool = False


class ZoneImportCreate(ImportSource):
    name: str = Field(max_length=253)
    description: str = Field(default="", max_length=255)
    # Only needed when the file has no SOA record.
    soa_rname: str | None = Field(default=None, max_length=253)


class ZoneImportInto(ImportSource):
    # merge: add what is missing. replace: the zone ends up with exactly the imported records.
    mode: Literal["merge", "replace"] = "merge"


class ReverseIn(BaseModel):
    network: str = Field(max_length=49)
    template: str = Field(max_length=253)
    ttl: int | None = None
    # Replace PTR records already at those addresses (otherwise they are kept and skipped).
    overwrite: bool = False
    # Also add the matching A/AAAA records in the hosted zone of each name (forward-confirmed reverse DNS).
    forward: bool = False
    dry_run: bool = False


# --------------------------------------------------------------------------- serialisation


def zone_out(z: Zone, record_count: int | None = None) -> dict:
    return {
        "id": z.id, "name": z.name, "description": z.description, "serial": z.serial, "default_ttl": z.default_ttl,
        "soa_mname": z.soa_mname, "soa_rname": z.soa_rname, "soa_refresh": z.soa_refresh, "soa_retry": z.soa_retry,
        "soa_expire": z.soa_expire, "soa_minimum": z.soa_minimum, "status": z.status, "dnssec": z.dnssec,
        "publish_state": z.publish_state, "pending": z.revision != z.published_revision,
        "published_serial": z.published_serial, "published_at": iso(z.published_at), "last_error": z.last_error,
        "record_count": record_count, "created_at": iso(z.created_at), "updated_at": iso(z.updated_at),
    }


def record_out(r: Record, zone_name: str) -> dict:
    fqdn = f"{zone_name}." if r.name == "@" else f"{r.name}.{zone_name}."
    return {
        "id": r.id, "name": r.name, "fqdn": fqdn, "type": r.type, "value": r.value, "ttl": r.ttl, "priority": r.priority,
        "disabled": r.disabled, "comment": r.comment, "updated_at": iso(r.updated_at),
    }


def record_snapshot(r: Record) -> dict:
    return {"name": r.name, "type": r.type, "value": r.value, "ttl": r.ttl, "priority": r.priority, "disabled": r.disabled}


# --------------------------------------------------------------------------- helpers


def _zone(db: Session, actor: Actor, zone_id: int, lock: bool = False) -> Zone:
    """The zone, if it exists and the caller may see it (a customer's other zones are 'not found')."""
    stmt = select(Zone).where(Zone.id == zone_id)
    if lock:
        stmt = stmt.with_for_update()
    zone = db.scalar(stmt)
    if zone is None or not actor.may_zone(db, zone.id):
        raise not_found("Zone")
    return zone


def _assign_creator(db: Session, actor: Actor, zone: Zone) -> None:
    """A customer or reseller who creates a zone gets it (others see every zone anyway)."""
    if not actor.all_zones:
        db.execute(insert(user_zones).values(user_id=actor.user.id, zone_id=zone.id))


def _touch(db: Session, zone: Zone) -> None:
    db.execute(update(Zone).where(Zone.id == zone.id).values(revision=Zone.revision + 1, publish_state="pending"))


def _soa_number(field: str, value: int) -> int:
    low, high = validation.SOA_BOUNDS[field]
    if not low <= value <= high:
        raise validation.ValidationError(field, f"Must be between {low} and {high} seconds.")
    return value


def _check_conflicts(db: Session, zone: Zone, name: str, rtype: str, enabled: bool, exclude_id: int | None) -> None:
    if not enabled:
        return
    others = select(Record.type).where(Record.zone_id == zone.id, Record.name == name, Record.disabled.is_(False))
    if exclude_id is not None:
        others = others.where(Record.id != exclude_id)
    problem = validation.conflict(name, rtype, set(db.scalars(others).all()))
    if problem:
        raise validation.ValidationError("type" if rtype in ("CNAME", "ALIAS") else "name", problem)


def _keeps_apex_ns(db: Session, zone: Zone, removing_id: int) -> None:
    remaining = db.scalar(
        select(func.count()).select_from(Record).where(
            Record.zone_id == zone.id, Record.name == "@", Record.type == "NS", Record.disabled.is_(False), Record.id != removing_id
        )
    )
    if not remaining:
        raise ApiError(422, "A zone needs at least one NS record at its apex. Add another name server first.")


def _quota(fn, *args) -> None:
    """Runs a quota check; over the limit, the transaction is rolled back and the caller gets a 422."""
    try:
        fn(*args)
    except quota.QuotaExceeded as exc:
        args[0].rollback()
        raise quota_error(exc) from None


def _ttl(value: int | None, field: str = "ttl") -> int | None:
    return validation.ttl(value, field)


def _integrity(exc: IntegrityError) -> ApiError:
    if "uq_records_rr" in str(exc.orig):
        return ApiError(409, "This exact record already exists in the zone.", {"value": "This exact record already exists."})
    if "uq_zones_name" in str(exc.orig):
        return ApiError(409, "A zone with this name already exists.", {"name": "A zone with this name already exists."})
    return ApiError(409, "The change conflicts with existing data.")


def _parse_source(body: ImportSource, origin: str, default_ttl: int = 3600) -> zoneio.ParsedZone:
    if (body.text is None) == (body.axfr is None):
        raise validation.ValidationError("text", "Paste a zone file or give a server to transfer the zone from (not both).")
    if body.text is not None:
        return zoneio.parse_text(body.text, origin, default_ttl)
    a = body.axfr
    return zoneio.fetch_axfr(origin, a.server, a.port, a.tsig_name, a.tsig_secret, a.tsig_algorithm)


def _soa_from_file(parsed: zoneio.ParsedZone, name: str) -> dict:
    """The SOA fields of a zone created from a file; timers out of DNSOne's range are clamped."""
    soa = parsed.soa or {}
    out = {}
    for field, key in (("soa_refresh", "refresh"), ("soa_retry", "retry"), ("soa_expire", "expire"), ("soa_minimum", "minimum")):
        low, high = validation.SOA_BOUNDS[field]
        if key in soa:
            value = min(max(int(soa[key]), low), high)
            if value != soa[key]:
                parsed.warnings.append(f"SOA {key} {soa[key]} changed to {value} (DNSOne allows {low}–{high} s)")
            out[field] = value
    if out.get("soa_retry", 1800) >= out.get("soa_refresh", 7200) or out.get("soa_expire", 1209600) <= out.get("soa_refresh", 7200) + out.get("soa_retry", 1800):
        parsed.warnings.append("SOA timers were inconsistent (retry ≥ refresh, or expire too short); DNSOne's defaults are used instead")
        out = {k: v for k, v in out.items() if k == "soa_minimum"}
    return out


def _import_report(parsed: zoneio.ParsedZone, added: list[zoneio.ImportedRecord], unchanged: int, removed: int = 0, updated: int = 0) -> dict:
    return {
        "added": len(added), "unchanged": unchanged, "removed": removed, "updated": updated,
        "skipped": parsed.skipped[:500], "skipped_count": len(parsed.skipped), "warnings": parsed.warnings[:500],
        "dnssec_dropped": parsed.dnssec_dropped, "records": [r.out() for r in added[:200]],
    }


def _missing_glue(parsed: zoneio.ParsedZone, name: str) -> list[str]:
    hosts = {r.name for r in parsed.records if r.type in ("A", "AAAA")}
    missing = []
    for ns in parsed.apex_ns():
        if ns == f"{name}." or ns.endswith(f".{name}."):
            owner = validation.owner_name(ns, name)
            if owner not in hosts:
                missing.append(ns)
    return missing


# --------------------------------------------------------------------------- zones


@router.get("")
def list_zones(
    q: str = Query("", max_length=253),
    status: Literal["", "active", "disabled"] = "",
    state: Literal["", "pending", "published", "error"] = "",
    sort: Literal["name", "-updated_at", "state"] = "name",
    paging: Paging = Depends(),
    actor: Actor = Depends(require("zones.view")),
    db: Session = Depends(get_db),
) -> dict:
    counts = select(func.count()).where(Record.zone_id == Zone.id).correlate(Zone).scalar_subquery()
    stmt = actor.zone_filter(select(Zone, counts.label("record_count")))
    if q:
        stmt = stmt.where(or_(Zone.name.like(like(q.strip().lower().rstrip("."))), Zone.description.like(like(q.strip()))))
    if status:
        stmt = stmt.where(Zone.status == status)
    if state:
        stmt = stmt.where(Zone.publish_state == state)
    order = {"name": [Zone.name], "-updated_at": [Zone.updated_at.desc(), Zone.name], "state": [Zone.publish_state, Zone.name]}[sort]
    stmt = stmt.order_by(*order)

    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    pages = max(1, -(-total // paging.size))
    page = min(paging.page, pages)
    rows = db.execute(stmt.limit(paging.size).offset((page - 1) * paging.size)).all()
    summary = dict(db.execute(actor.zone_filter(select(Zone.publish_state, func.count())).group_by(Zone.publish_state)).all())
    return {
        "rows": [zone_out(z, c) for z, c in rows], "total": total, "page": page, "pages": pages, "size": paging.size,
        "summary": {"published": summary.get("published", 0), "pending": summary.get("pending", 0), "error": summary.get("error", 0)},
    }


@router.post("", status_code=201)
def create_zone(body: ZoneCreate, background: BackgroundTasks, actor: Actor = Depends(require("zones.create")), db: Session = Depends(get_db)) -> dict:
    try:
        name = validation.zone_name(body.name)
        ttl = validation.ttl(body.default_ttl, "default_ttl", allow_none=False)
        rname = validation.mailbox(body.soa_rname, name)
        hosts: list[tuple[str, str | None]] = []
        for i, ns in enumerate(body.nameservers):
            host = validation.absolute_name(ns.host, name, f"nameservers.{i}.host")
            in_zone = host == f"{name}." or host.endswith(f".{name}.")
            raw = (ns.address or "").strip()
            address = None
            if in_zone and not raw:
                raise validation.ValidationError(f"nameservers.{i}.address", f"{host} is inside the zone, so it needs an IP address (glue).")
            if raw and not in_zone:
                raise validation.ValidationError(f"nameservers.{i}.address", f"{host} is outside the zone; its address is published by its own zone, leave this empty.")
            if raw:
                try:
                    _, _, address, _ = validation.record(name, host, "AAAA" if ":" in raw else "A", raw, None)
                except validation.ValidationError as exc:
                    raise validation.ValidationError(f"nameservers.{i}.address", exc.message) from None
            hosts.append((host, address))
        if len({h for h, _ in hosts}) != len(hosts):
            raise validation.ValidationError("nameservers", "Each name server can be listed once.")
        template = templates.get(db, body.template_id) if body.template_id else None
        extra = templates.render(template, name, body.variables) if template else []
    except validation.ValidationError as exc:
        raise field_error(exc) from None

    _quota(quota.check_zones, db, actor.user)
    zone = Zone(name=name, description=body.description.strip(), default_ttl=ttl, soa_mname=hosts[0][0], soa_rname=rname,
                serial=next_serial(0), status="active", revision=1, published_revision=0, publish_state="pending")
    db.add(zone)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _integrity(exc) from None
    _assign_creator(db, actor, zone)
    added: dict[tuple, Record] = {}
    for host, address in hosts:
        added[("@", "NS", None, host)] = Record(zone_id=zone.id, name="@", type="NS", value=host)
        if address:
            owner = validation.owner_name(host, name)
            rtype = "AAAA" if ":" in address else "A"
            added[(owner, rtype, None, address)] = Record(zone_id=zone.id, name=owner, type=rtype, value=address)
    skipped = _add_rendered(added, extra, zone.id)
    _quota(quota.check_records, db, actor.user, zone.id, len(added))
    db.add_all(added.values())
    audit.record(db, actor.name, "zone.created", "zone", zone.id, {"name": name, "nameservers": [h for h, _ in hosts],
                 **({"template": template.name, "records": len(added), "skipped": skipped} if template else {})}, actor.ip)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise _integrity(exc) from None
    background.add_task(publish_in_background, zone.id)
    return {**zone_out(zone, len(added)), "skipped": skipped}


def _add_rendered(added: dict[tuple, Record], rendered: list[templates.Rendered], zone_id: int, existing: dict[str, set[str]] | None = None) -> list[str]:
    """Adds template records to `added` (keyed like uq_records_rr), skipping duplicates and conflicts."""
    types: dict[str, set[str]] = {k: set(v) for k, v in (existing or {}).items()}
    for r in added.values():
        types.setdefault(r.name, set()).add(r.type)
    skipped = []
    for r in rendered:
        if r.key() in added:
            continue
        problem = validation.conflict(r.name, r.type, types.get(r.name, set()))
        if problem:
            skipped.append(f"{r.name} {r.type} {r.value}: {problem}")
            continue
        types.setdefault(r.name, set()).add(r.type)
        added[r.key()] = Record(zone_id=zone_id, name=r.name, type=r.type, value=r.value, ttl=r.ttl, priority=r.priority, comment=r.comment)
    return skipped


@router.post("/import", status_code=201)
def import_zone(body: ZoneImportCreate, background: BackgroundTasks, actor: Actor = Depends(require("zones.create")), db: Session = Depends(get_db)) -> dict:
    """Creates a zone from a zone file or an AXFR: SOA, name servers and every supported record."""
    try:
        name = validation.zone_name(body.name)
        if db.scalar(select(Zone.id).where(Zone.name == name)):
            raise ApiError(409, "A zone with this name already exists. Open it and use Import to add or replace its records.", {"name": "A zone with this name already exists."})
        parsed = _parse_source(body, name)
        if not parsed.apex_ns():
            raise validation.ValidationError("text", f"The zone has no NS records at its apex ({name}); a zone needs at least one name server.")
        missing = _missing_glue(parsed, name)
        if missing:
            raise validation.ValidationError("text", f"{', '.join(missing)} is inside the zone but has no A/AAAA record (glue).")
        if parsed.soa:
            rname = validation.mailbox(parsed.soa["rname"], name)
            mname = validation.absolute_name(parsed.soa["mname"], name, "text")
        elif body.soa_rname:
            rname = validation.mailbox(body.soa_rname, name)
            mname = parsed.apex_ns()[0]
        else:
            raise validation.ValidationError("soa_rname", "The file has no SOA record: enter the zone's contact email.")
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    soa = _soa_from_file(parsed, name)
    ttl = zoneio.default_ttl(parsed)
    zoneio.apply_default_ttl(parsed, ttl)
    if body.dry_run:
        return {**_import_report(parsed, parsed.records, 0), "zone": {"name": name, "default_ttl": ttl, "soa_mname": mname, "soa_rname": rname, **soa}}

    _quota(quota.check_zones, db, actor.user)
    _quota(quota.check_records, db, actor.user, 0, len(parsed.records))
    # Keep the old server's serial: secondaries and caches that hold it then accept the next one.
    file_serial = int((parsed.soa or {}).get("serial") or 0)
    zone = Zone(name=name, description=body.description.strip(), default_ttl=ttl, soa_mname=mname, soa_rname=rname,
                serial=file_serial if 0 < file_serial < 2**32 - 1 else next_serial(0),
                status="active", revision=1, published_revision=0, publish_state="pending", **soa)
    db.add(zone)
    try:
        db.flush()
        db.add_all(Record(zone_id=zone.id, name=r.name, type=r.type, value=r.value, ttl=r.ttl, priority=r.priority) for r in parsed.records)
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _integrity(exc) from None
    _assign_creator(db, actor, zone)
    source = f"AXFR from {body.axfr.server}" if body.axfr else "zone file"
    audit.record(db, actor.name, "zone.imported", "zone", zone.id, {"name": name, "source": source, "records": len(parsed.records),
                 "skipped": len(parsed.skipped), "created": True}, actor.ip)
    db.commit()
    background.add_task(publish_in_background, zone.id)
    return {**_import_report(parsed, parsed.records, 0), "zone": zone_out(zone, len(parsed.records))}


@router.get("/{zone_id}")
def get_zone(zone_id: int, actor: Actor = Depends(require("zones.view")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id)
    count = db.scalar(select(func.count()).select_from(Record).where(Record.zone_id == zone.id))
    types = dict(db.execute(select(Record.type, func.count()).where(Record.zone_id == zone.id).group_by(Record.type)).all())
    return {**zone_out(zone, count), "type_counts": types}


@router.patch("/{zone_id}")
def update_zone(zone_id: int, body: ZoneUpdate, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id, lock=True)
    before = zone_out(zone)
    changes = body.model_dump(exclude_unset=True)
    try:
        if "description" in changes and body.description is not None:
            zone.description = body.description.strip()
        if body.default_ttl is not None:
            zone.default_ttl = validation.ttl(body.default_ttl, "default_ttl", allow_none=False)
        if body.soa_mname is not None:
            zone.soa_mname = validation.absolute_name(body.soa_mname, zone.name, "soa_mname")
        if body.soa_rname is not None:
            zone.soa_rname = validation.mailbox(body.soa_rname, zone.name)
        for field in ("soa_refresh", "soa_retry", "soa_expire", "soa_minimum"):
            value = getattr(body, field)
            if value is not None:
                setattr(zone, field, _soa_number(field, value))
        if zone.soa_retry >= zone.soa_refresh:
            raise validation.ValidationError("soa_retry", "Retry should be shorter than refresh.")
        if zone.soa_expire <= zone.soa_refresh + zone.soa_retry:
            raise validation.ValidationError("soa_expire", "Expire must be longer than refresh plus retry.")
        if body.status is not None:
            zone.status = body.status
        if body.dnssec is True:
            zone.dnssec = "on"
        elif body.dnssec is False and zone.dnssec == "on":
            # BIND removes the keys once told the DS is gone; a DS still at the parent would then make the
            # zone bogus (SERVFAIL) for every validating resolver. A parent hosted here: DNSOne removes it.
            if dnssec.hosted_parent(db, zone.name) is None and dnssec.parent_ds(zone.name):
                raise ApiError(409, "The parent zone still publishes DS records for this zone. Remove them at the registrar, wait a day for caches to expire, then turn signing off.",
                               {"dnssec": "Remove the DS records at the registrar first."})
            zone.dnssec = "insecure"
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    except ApiError:
        db.rollback()
        raise
    zone.revision += 1
    zone.publish_state = "pending"
    after = zone_out(zone)
    diff = {k: {"from": before[k], "to": after[k]} for k in changes if k in after and before[k] != after[k]}
    audit.record(db, actor.name, "zone.updated", "zone", zone.id, {"name": zone.name, "changes": diff}, actor.ip)
    db.commit()
    background.add_task(publish_in_background, zone.id)
    return zone_out(zone)


@router.delete("/{zone_id}")
def delete_zone(zone_id: int, background: BackgroundTasks, actor: Actor = Depends(require("zones.create")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id, lock=True)
    name = zone.name
    count = db.scalar(select(func.count()).select_from(Record).where(Record.zone_id == zone.id))
    audit.record(db, actor.name, "zone.deleted", "zone", zone.id, {"name": name, "records": count}, actor.ip)
    db.delete(zone)
    db.commit()
    background.add_task(remove_in_background, name)
    return {"ok": True}


@router.post("/{zone_id}/publish")
def publish_zone(zone_id: int, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id)
    audit.record(db, actor.name, "zone.publish_requested", "zone", zone.id, {"name": zone.name}, actor.ip)
    db.commit()
    try:
        result = Publisher().publish(zone.id, force=True)
    except TimeoutError as exc:
        raise ApiError(409, str(exc)) from None
    db.expire_all()
    zone = _zone(db, actor, zone_id)
    if not result.ok:
        raise ApiError(422, result.message)
    return {**zone_out(zone), "message": result.message}


@router.get("/{zone_id}/preview")
def preview_zone(zone_id: int, actor: Actor = Depends(require("zones.view")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id)
    records = list(db.scalars(select(Record).where(Record.zone_id == zone.id)))
    serial = next_serial(max(zone.serial, zone.published_serial or 0)) if zone.revision != zone.published_revision else zone.serial
    return {"text": render_zone(zone, records, serial), "serial": serial}


@router.get("/{zone_id}/dnssec")
def zone_dnssec(zone_id: int, actor: Actor = Depends(require("zones.view")), db: Session = Depends(get_db)) -> dict:
    """Signing state: the keys BIND serves, the DS records for the registrar, and what the parent has."""
    zone = _zone(db, actor, zone_id)
    return {"state": zone.dnssec, **dnssec.describe(zone.name, zone.dnssec, db=db)}


@router.post("/{zone_id}/dnssec/check")
def check_dnssec(zone_id: int, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    """Does now what the reconcile job does every 5 minutes: the hosted parent's DS records, and BIND told
    whether the parent publishes the DS."""
    zone = _zone(db, actor, zone_id)
    if zone.dnssec == "off":
        raise ApiError(422, "The zone is not signed.")
    try:
        done = dnssec.sync_zone(db, zone, Publisher().publish)
    except TimeoutError as exc:
        raise ApiError(409, str(exc)) from None
    if done:
        audit.record(db, actor.name, "zone.dnssec_checked", "zone", zone.id, {"name": zone.name, "done": done}, actor.ip)
        db.commit()
    db.expire_all()
    return {"done": done, "state": zone.dnssec, **dnssec.describe(zone.name, zone.dnssec, db=db)}


@router.post("/{zone_id}/dnssec/rollover")
def rollover_dnssec(zone_id: int, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    """Rolls the zone's signing key: the new key's DS must reach the parent before the old key goes."""
    zone = _zone(db, actor, zone_id)
    if zone.dnssec != "on":
        raise ApiError(422, "The zone is not signed.")
    ok, message = dnssec.rollover(zone.name)
    if not ok:
        raise ApiError(409, message)
    audit.record(db, actor.name, "zone.dnssec_rollover", "zone", zone.id, {"name": zone.name, "message": message}, actor.ip)
    db.commit()
    return {"message": message, "state": zone.dnssec, **dnssec.describe(zone.name, zone.dnssec, db=db)}


@router.get("/{zone_id}/export", response_class=PlainTextResponse)
def export_zone(zone_id: int, actor: Actor = Depends(require("zones.view")), db: Session = Depends(get_db)) -> PlainTextResponse:
    """The zone as a BIND zone file (what the next publish writes), as a download."""
    zone = _zone(db, actor, zone_id)
    records = list(db.scalars(select(Record).where(Record.zone_id == zone.id)))
    serial = next_serial(max(zone.serial, zone.published_serial or 0)) if zone.revision != zone.published_revision else zone.serial
    return PlainTextResponse(render_zone(zone, records, serial), headers={"Content-Disposition": f'attachment; filename="{zone.name}.zone"'})


@router.post("/{zone_id}/import")
def import_records(zone_id: int, body: ZoneImportInto, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    """Adds records from a zone file or AXFR to this zone (merge), or makes the zone match it (replace)."""
    zone = _zone(db, actor, zone_id, lock=True)
    try:
        parsed = _parse_source(body, zone.name, zone.default_ttl)
        if body.mode == "replace":
            if not parsed.apex_ns():
                raise validation.ValidationError("text", "Replacing needs NS records at the apex in the import: a zone needs at least one name server.")
            missing = _missing_glue(parsed, zone.name)
            if missing:
                raise validation.ValidationError("text", f"{', '.join(missing)} is inside the zone but has no A/AAAA record (glue).")
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    zoneio.apply_default_ttl(parsed, zone.default_ttl)

    existing = list(db.scalars(select(Record).where(Record.zone_id == zone.id)))
    by_key = {(r.name, r.type, r.priority, r.value): r for r in existing}
    imported = {r.key: r for r in parsed.records}
    added: list[zoneio.ImportedRecord] = []
    removed: list[Record] = []
    updated = 0
    if body.mode == "replace":
        removed = [r for k, r in by_key.items() if k not in imported]
        for key, rec in imported.items():
            if key not in by_key:
                added.append(rec)
            elif by_key[key].ttl != rec.ttl or by_key[key].disabled:
                updated += 1
    else:
        # The names' types once the merge is done, to keep a CNAME alone at its name.
        types: dict[str, set[str]] = {}
        for r in existing:
            if not r.disabled:
                types.setdefault(r.name, set()).add(r.type)
        for key, rec in imported.items():
            if key in by_key:
                continue
            problem = validation.conflict(rec.name, rec.type, types.get(rec.name, set()))
            if problem:
                parsed.skipped.append(f"{rec.name} {rec.type} {rec.value[:80]}: {problem}")
                continue
            types.setdefault(rec.name, set()).add(rec.type)
            added.append(rec)
    unchanged = len(imported) - len(added) - updated if body.mode == "replace" else sum(1 for k in imported if k in by_key)
    report = _import_report(parsed, added, unchanged, len(removed), updated)
    _quota(quota.check_records, db, actor.user, zone.id, len(added) - len(removed))
    if body.dry_run or not (added or removed or updated):
        db.rollback()
        return report

    if removed:
        db.execute(delete(Record).where(Record.id.in_([r.id for r in removed])))
    if body.mode == "replace":
        for key, rec in imported.items():
            row = by_key.get(key)
            if row is not None and (row.ttl != rec.ttl or row.disabled):
                row.ttl, row.disabled = rec.ttl, False
    db.add_all(Record(zone_id=zone.id, name=r.name, type=r.type, value=r.value, ttl=r.ttl, priority=r.priority) for r in added)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _integrity(exc) from None
    _touch(db, zone)
    source = f"AXFR from {body.axfr.server}" if body.axfr else "zone file"
    audit.record(db, actor.name, "zone.imported", "zone", zone.id, {"name": zone.name, "source": source, "mode": body.mode,
                 "added": len(added), "removed": len(removed), "updated": updated, "skipped": len(parsed.skipped)}, actor.ip)
    db.commit()
    background.add_task(publish_in_background, zone.id)
    return report


def _forward_plan(db: Session, actor: Actor, names: list[tuple[str, str, str]], overwrite: bool) -> tuple[dict[int, list[dict]], dict[int, list[int]], dict[int, str], list[str]]:
    """A/AAAA records for generated PTR targets, in the hosted zone each name belongs to.

    Returns (rows to add per zone id, record ids to remove per zone id, zone names, skipped).
    A name that already has an address record is skipped unless overwrite; one with a CNAME always is.
    """
    zones = sorted(db.execute(actor.zone_filter(select(Zone.id, Zone.name))).all(), key=lambda z: -len(z.name))
    add: dict[int, list[dict]] = {}
    remove: dict[int, list[int]] = {}
    found: dict[int, str] = {}
    skipped: list[str] = []
    targets: dict[int, list[tuple[str, str]]] = {}
    for _, address, host in names:
        fqdn = host.rstrip(".")
        zone = next(((zid, zname) for zid, zname in zones if fqdn == zname or fqdn.endswith(f".{zname}")), None)
        if zone is None:
            skipped.append(f"{host}: no hosted zone for this name, so no {'AAAA' if ':' in address else 'A'} record")
            continue
        found[zone[0]] = zone[1]
        owner = validation.owner_name(host, zone[1])
        targets.setdefault(zone[0], []).append((owner, address))
    for zid, items in targets.items():
        owners = {o for o, _ in items}
        existing: dict[str, list[Record]] = {}
        for row in db.scalars(select(Record).where(Record.zone_id == zid, Record.type.in_(("A", "AAAA", "CNAME")))):
            if row.name in owners:
                existing.setdefault(row.name, []).append(row)
        for owner, address in items:
            rtype = "AAAA" if ":" in address else "A"
            have = existing.get(owner, [])
            if any(r.type == "CNAME" for r in have):
                skipped.append(f"{owner}.{found[zid]}: has a CNAME, so no {rtype} record")
                continue
            same = [r for r in have if r.type == rtype]
            if any(r.value == address for r in same) and len(same) == 1:
                continue
            if same and not overwrite:
                skipped.append(f"{owner}.{found[zid]}: already has an {rtype} record (turn on overwrite to replace it)")
                continue
            remove.setdefault(zid, []).extend(r.id for r in same)
            add.setdefault(zid, []).append({"name": owner, "type": rtype, "value": address})
    return add, remove, found, skipped


@router.post("/{zone_id}/reverse")
def generate_reverse(zone_id: int, body: ReverseIn, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    """PTR records for a whole subnet from a name pattern (e.g. customer address pools)."""
    zone = _zone(db, actor, zone_id, lock=True)
    try:
        names = zoneio.reverse_names(zone.name, body.network, body.template)
        ttl = _ttl(body.ttl)
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    owners = {o for o, _, _ in names}
    existing: dict[str, list[Record]] = {}
    for row in db.scalars(select(Record).where(Record.zone_id == zone.id, Record.name.in_(owners)) if len(owners) <= 1000
                          else select(Record).where(Record.zone_id == zone.id)):
        if row.name in owners:
            existing.setdefault(row.name, []).append(row)
    rows, remove, skipped, unchanged = [], [], [], 0
    # Addresses whose PTR will point to the generated name: the ones forward records are made for.
    kept: list[tuple[str, str, str]] = []
    for owner, address, host in names:
        have = existing.get(owner, [])
        if any(r.type != "PTR" for r in have):
            skipped.append(f"{address}: {owner} has {', '.join(sorted({r.type for r in have if r.type != 'PTR'}))} records (e.g. a delegation CNAME)")
            continue
        kept.append((owner, address, host))
        if len(have) == 1 and have[0].value == host and have[0].ttl == ttl:
            unchanged += 1
            continue
        if have and not body.overwrite:
            kept.pop()
            skipped.append(f"{address}: already points to {have[0].value} (turn on overwrite to replace it)")
            continue
        remove.extend(r.id for r in have)
        rows.append({"zone_id": zone.id, "name": owner, "type": "PTR", "value": host, "ttl": ttl})
    forward_add, forward_remove, forward_zones, forward_skipped = ({}, {}, {}, [])
    if body.forward:
        forward_add, forward_remove, forward_zones, forward_skipped = _forward_plan(db, actor, kept, body.overwrite)
    report = {
        "addresses": len(names), "added": len(rows), "replaced": len(remove), "unchanged": unchanged,
        "skipped": skipped[:500], "skipped_count": len(skipped),
        "sample": [{"address": a, "name": o, "value": h} for o, a, h in names[:5]],
        "forward": {"added": sum(len(v) for v in forward_add.values()), "replaced": sum(len(v) for v in forward_remove.values()),
                    "zones": sorted(forward_zones[z] for z in forward_add), "skipped": forward_skipped[:500], "skipped_count": len(forward_skipped)},
    }
    _quota(quota.check_records, db, actor.user, zone.id, len(rows) - len(remove))
    for zid, items in forward_add.items():
        _quota(quota.check_records, db, actor.user, zid, len(items) - len(forward_remove.get(zid, [])))
    if body.dry_run or not (rows or remove or forward_add):
        db.rollback()
        return report

    if remove:
        db.execute(delete(Record).where(Record.id.in_(remove)))
    if rows:
        db.execute(insert(Record), rows)
    if rows or remove:
        _touch(db, zone)
    for zid, items in forward_add.items():
        locked = _zone(db, actor, zid, lock=True)
        if forward_remove.get(zid):
            db.execute(delete(Record).where(Record.id.in_(forward_remove[zid])))
        db.execute(insert(Record), [{"zone_id": zid, "ttl": ttl, **item} for item in items])
        _touch(db, locked)
    audit.record(db, actor.name, "zone.reverse_generated", "zone", zone.id, {"name": zone.name, "network": body.network, "template": body.template,
                 "added": len(rows), "replaced": len(remove), "forward": report["forward"]["added"]}, actor.ip)
    db.commit()
    background.add_task(publish_in_background, zone.id)
    for zid in forward_add:
        background.add_task(publish_in_background, zid)
    return report


@router.post("/{zone_id}/template")
def apply_template(zone_id: int, body: TemplateApply, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    """Adds a template's records to the zone; records already there or conflicting with it are skipped."""
    zone = _zone(db, actor, zone_id, lock=True)
    try:
        template = templates.get(db, body.template_id)
        rendered = templates.render(template, zone.name, body.variables)
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    existing_keys: dict[tuple, Record] = {}
    types: dict[str, set[str]] = {}
    for r in db.scalars(select(Record).where(Record.zone_id == zone.id)):
        existing_keys[(r.name, r.type, r.priority, r.value)] = r
        if not r.disabled:
            types.setdefault(r.name, set()).add(r.type)
    added: dict[tuple, Record] = dict(existing_keys)
    skipped = _add_rendered(added, rendered, zone.id, types)
    new = [r for k, r in added.items() if k not in existing_keys]
    report = {"added": len(new), "unchanged": len(rendered) - len(new) - len(skipped), "skipped": skipped,
              "records": [record_snapshot(r) for r in new[:200]]}
    _quota(quota.check_records, db, actor.user, zone.id, len(new))
    if body.dry_run or not new:
        db.rollback()
        return report
    db.add_all(new)
    db.flush()
    _touch(db, zone)
    audit.record(db, actor.name, "zone.template_applied", "zone", zone.id, {"name": zone.name, "template": template.name,
                 "added": len(new), "skipped": len(skipped)}, actor.ip)
    db.commit()
    background.add_task(publish_in_background, zone.id)
    return report


# --------------------------------------------------------------------------- history


def version_out(v: ZoneVersion) -> dict:
    return {"id": v.id, "serial": v.serial, "record_count": v.record_count, "changes": v.changes or {}, "actors": v.actors or [], "created_at": iso(v.created_at)}


def _version(db: Session, zone: Zone, version_id: int) -> ZoneVersion:
    version = db.scalar(select(ZoneVersion).where(ZoneVersion.id == version_id, ZoneVersion.zone_id == zone.id))
    if version is None:
        raise not_found("Version")
    return version


@router.get("/{zone_id}/versions")
def list_versions(zone_id: int, paging: Paging = Depends(), actor: Actor = Depends(require("zones.view")), db: Session = Depends(get_db)) -> dict:
    """Every published version of the zone, newest first (the first one is what is live now)."""
    zone = _zone(db, actor, zone_id)
    stmt = select(ZoneVersion).where(ZoneVersion.zone_id == zone.id).order_by(ZoneVersion.id.desc())
    return paging.apply(db, stmt, version_out)


@router.get("/{zone_id}/versions/{version_id}")
def get_version(zone_id: int, version_id: int, actor: Actor = Depends(require("zones.view")), db: Session = Depends(get_db)) -> dict:
    """A version, what it changed from the one before, and what rolling back to it would change now."""
    zone = _zone(db, actor, zone_id)
    version = _version(db, zone, version_id)
    data = history.load(version)
    previous = db.scalar(select(ZoneVersion).where(ZoneVersion.zone_id == zone.id, ZoneVersion.id < version.id).order_by(ZoneVersion.id.desc()).limit(1))
    since = history.diff(history.load(previous) if previous else None, data)
    rollback = history.diff(history.current(db, zone), data)
    cap = lambda d: {k: v[:500] if isinstance(v, list) else v for k, v in d.items()}
    return {**version_out(version), "zone": data["zone"], "records": data["records"][:2000], "record_total": len(data["records"]),
            "diff": cap(since), "rollback": {**cap(rollback), "summary": history.summary(rollback)}, "first": previous is None}


@router.post("/{zone_id}/versions/{version_id}/restore")
def restore_version(zone_id: int, version_id: int, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    """Rolls the zone's settings and records back to a version, as one new change."""
    zone = _zone(db, actor, zone_id, lock=True)
    version = _version(db, zone, version_id)
    data = history.load(version)
    change = history.diff(history.current(db, zone), data)
    if not (change["added"] or change["removed"] or change["changed"] or change["settings"]):
        db.rollback()
        return {"message": "The zone already matches this version.", "summary": history.summary(change)}
    if not any(r["name"] == "@" and r["type"] == "NS" and not r["disabled"] for r in data["records"]):
        raise ApiError(422, "That version has no NS records at the apex; it cannot be restored.")
    current = db.scalar(select(func.count()).select_from(Record).where(Record.zone_id == zone.id)) or 0
    _quota(quota.check_records, db, actor.user, zone.id, len(data["records"]) - current)
    for field, value in data["zone"].items():
        setattr(zone, field, value)
    db.execute(delete(Record).where(Record.zone_id == zone.id))
    db.flush()
    db.add_all(Record(zone_id=zone.id, **r) for r in data["records"])
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _integrity(exc) from None
    zone.revision += 1
    zone.publish_state = "pending"
    summary = history.summary(change)
    audit.record(db, actor.name, "zone.rolled_back", "zone", zone.id, {"name": zone.name, "version": version.id, "serial": version.serial, **summary}, actor.ip)
    db.commit()
    background.add_task(publish_in_background, zone.id)
    return {"message": f"Rolled back to the version of serial {version.serial}. Publishing…", "summary": summary}


# --------------------------------------------------------------------------- records


@router.get("/{zone_id}/records")
def list_records(
    zone_id: int,
    q: str = Query("", max_length=253),
    type: str = Query("", max_length=5),
    paging: Paging = Depends(),
    actor: Actor = Depends(require("zones.view")),
    db: Session = Depends(get_db),
) -> dict:
    zone = _zone(db, actor, zone_id)
    stmt = select(Record).where(Record.zone_id == zone.id)
    if q:
        term = like(q.strip())
        stmt = stmt.where(or_(Record.name.like(term), Record.value.like(term), Record.comment.like(term)))
    if type:
        if type.upper() not in validation.RECORD_TYPES:
            raise ApiError(422, "Unknown record type.", {"type": "Unknown record type."})
        stmt = stmt.where(Record.type == type.upper())
    stmt = stmt.order_by(Record.name != "@", Record.name, Record.type, Record.priority, Record.value)
    return paging.apply(db, stmt, lambda r: record_out(r, zone.name))


@router.post("/{zone_id}/records", status_code=201)
def create_record(zone_id: int, body: RecordIn, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id, lock=True)
    try:
        name, rtype, value, priority = validation.record(zone.name, body.name, body.type, body.value, body.priority)
        ttl = _ttl(body.ttl)
        _check_conflicts(db, zone, name, rtype, not body.disabled, None)
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    _quota(quota.check_records, db, actor.user, zone.id, 1)
    rec = Record(zone_id=zone.id, name=name, type=rtype, value=value, ttl=ttl, priority=priority, disabled=body.disabled, comment=body.comment.strip())
    db.add(rec)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _integrity(exc) from None
    _touch(db, zone)
    audit.record(db, actor.name, "record.created", "record", rec.id, {"zone": zone.name, **record_snapshot(rec)}, actor.ip)
    db.commit()
    background.add_task(publish_in_background, zone.id)
    return record_out(rec, zone.name)


@router.patch("/{zone_id}/records/{record_id}")
def update_record(zone_id: int, record_id: int, body: RecordPatch, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id, lock=True)
    rec = db.scalar(select(Record).where(Record.id == record_id, Record.zone_id == zone.id))
    if rec is None:
        raise not_found("Record")
    before = record_snapshot(rec)
    rtype = body.type if body.type is not None else rec.type
    raw_value = body.value if body.value is not None else rec.value
    priority = body.priority if body.priority is not None else rec.priority
    disabled = body.disabled if body.disabled is not None else rec.disabled
    try:
        name, rtype, value, priority = validation.record(zone.name, body.name if body.name is not None else rec.name, rtype, raw_value, priority)
        ttl = None if body.clear_ttl else (_ttl(body.ttl) if body.ttl is not None else rec.ttl)
        _check_conflicts(db, zone, name, rtype, not disabled, rec.id)
        was_apex_ns = rec.name == "@" and rec.type == "NS" and not rec.disabled
        if was_apex_ns and (name != "@" or rtype != "NS" or disabled):
            _keeps_apex_ns(db, zone, rec.id)
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    rec.name, rec.type, rec.value, rec.ttl, rec.priority, rec.disabled = name, rtype, value, ttl, priority, disabled
    if body.comment is not None:
        rec.comment = body.comment.strip()
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise _integrity(exc) from None
    after = record_snapshot(rec)
    if before != after or body.comment is not None:
        _touch(db, zone)
        audit.record(db, actor.name, "record.updated", "record", rec.id, {"zone": zone.name, "from": before, "to": after}, actor.ip)
    db.commit()
    background.add_task(publish_in_background, zone.id)
    db.refresh(rec)
    return record_out(rec, zone.name)


@router.delete("/{zone_id}/records/{record_id}")
def delete_record(zone_id: int, record_id: int, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id, lock=True)
    rec = db.scalar(select(Record).where(Record.id == record_id, Record.zone_id == zone.id))
    if rec is None:
        raise not_found("Record")
    if rec.name == "@" and rec.type == "NS" and not rec.disabled:
        _keeps_apex_ns(db, zone, rec.id)
    audit.record(db, actor.name, "record.deleted", "record", rec.id, {"zone": zone.name, **record_snapshot(rec)}, actor.ip)
    db.delete(rec)
    _touch(db, zone)
    db.commit()
    background.add_task(publish_in_background, zone.id)
    return {"ok": True}
