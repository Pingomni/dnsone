# SPDX-License-Identifier: Elastic-2.0
# DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
"""Zone → Transfers: the secondaries a zone's owner lets transfer it, and its transfer key (transfers.py)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, runtime, transfers, validation
from ..db import get_db
from ..models import ZoneTransfer
from ..security import iso
from ..zonegen import publish_in_background
from .deps import Actor, ApiError, field_error, not_found, require
from .zones import _touch, _zone

router = APIRouter(tags=["transfers"])

Algorithm = Literal["hmac-sha256", "hmac-sha512", "hmac-sha384", "hmac-sha224", "hmac-sha1"]


class TransferIn(BaseModel):
    address: str = Field(max_length=49)
    notify: bool = True
    notify_port: int = Field(default=53, ge=1, le=65535)
    comment: str = Field(default="", max_length=255)


class KeyIn(BaseModel):
    enabled: bool
    algorithm: Algorithm = "hmac-sha256"
    # Empty: a new random secret.
    secret: str = Field(default="", max_length=128)


def transfer_out(t: ZoneTransfer) -> dict:
    return {"id": t.id, "address": t.address, "notify": t.notify and transfers.is_single(t.address), "notify_port": t.notify_port,
            "network": not transfers.is_single(t.address), "comment": t.comment, "created_by": t.created_by, "created_at": iso(t.created_at)}


def _state(db: Session, zone) -> dict:
    return {
        "rows": [transfer_out(t) for t in transfers.entries(db, zone.id)],
        "key": {"enabled": zone.xfr_key_name is not None, "name": zone.xfr_key_name, "algorithm": zone.xfr_key_algorithm},
        "max": transfers.MAX_PER_ZONE,
    }


def _after(background: BackgroundTasks, zone_id: int) -> None:
    # zones.conf (BIND's allow-transfer, also-notify, key) is rewritten by the publish; dnsdist's list by runtime.apply.
    background.add_task(publish_in_background, zone_id)
    background.add_task(runtime.apply_in_background)


@router.get("/api/zones/{zone_id}/transfers")
def list_transfers(zone_id: int, actor: Actor = Depends(require("zones.view")), db: Session = Depends(get_db)) -> dict:
    return _state(db, _zone(db, actor, zone_id))


@router.post("/api/zones/{zone_id}/transfers", status_code=201)
def add_transfer(zone_id: int, body: TransferIn, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id, lock=True)
    try:
        address = transfers.clean_address(body.address)
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    count = db.scalar(select(func.count()).select_from(ZoneTransfer).where(ZoneTransfer.zone_id == zone.id)) or 0
    if count >= transfers.MAX_PER_ZONE:
        db.rollback()
        raise ApiError(422, f"A zone can list at most {transfers.MAX_PER_ZONE} secondaries; use a network for several addresses.", {"address": "Too many entries."})
    row = ZoneTransfer(zone_id=zone.id, address=address, notify=body.notify and transfers.is_single(address), notify_port=body.notify_port,
                       comment=body.comment.strip(), created_by=actor.name)
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "This address is already listed.", {"address": "Already listed."}) from None
    _touch(db, zone)
    audit.record(db, actor.name, "zone.transfer_added", "zone", zone.id, {"name": zone.name, "address": address, "notify": row.notify}, actor.ip)
    db.commit()
    _after(background, zone.id)
    return transfer_out(row)


@router.delete("/api/zones/{zone_id}/transfers/{transfer_id}")
def remove_transfer(zone_id: int, transfer_id: int, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id, lock=True)
    row = db.get(ZoneTransfer, transfer_id)
    if row is None or row.zone_id != zone.id:
        db.rollback()
        raise not_found("Secondary")
    audit.record(db, actor.name, "zone.transfer_removed", "zone", zone.id, {"name": zone.name, "address": row.address}, actor.ip)
    db.delete(row)
    _touch(db, zone)
    db.commit()
    _after(background, zone.id)
    return {"ok": True}


@router.put("/api/zones/{zone_id}/transfers/key")
def set_key(zone_id: int, body: KeyIn, background: BackgroundTasks, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    """Turns the zone's transfer key on (a new secret each time, shown once) or off."""
    zone = _zone(db, actor, zone_id, lock=True)
    try:
        changed = transfers.set_key(zone, body.enabled, body.algorithm, body.secret)
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    if changed:
        _touch(db, zone)
        audit.record(db, actor.name, "zone.transfer_key_set" if body.enabled else "zone.transfer_key_removed", "zone", zone.id,
                     {"name": zone.name, "key": zone.xfr_key_name, "algorithm": zone.xfr_key_algorithm}, actor.ip)
    db.commit()
    _after(background, zone.id)
    out = _state(db, zone)
    if body.enabled:
        out["key"]["secret"] = zone.xfr_key_secret
    return out
