"""Protection page: what dnsdist is blocking (dynamic blocks), its history, thresholds and manual blocks."""

from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, protection, runtime, validation
from ..config import get_settings
from ..db import get_db
from ..models import AttackEvent, ProtectionBlock
from ..security import iso
from ..system import utcnow
from .deps import Actor, ApiError, Paging, field_error, like, not_found, require

router = APIRouter(prefix="/api/protection", tags=["protection"])

Kind = Literal["", "flood", "servfail", "nxdomain", "amplification", "random-subdomain"]


class BlockIn(BaseModel):
    kind: Literal["client", "domain"]
    value: str = Field(max_length=253)
    reason: str = Field(default="", max_length=255)
    # 0: until removed.
    minutes: int = Field(default=0, ge=0, le=525600)


def event_out(e: AttackEvent) -> dict:
    return {"id": e.id, "node": e.node, "kind": e.kind, "target": e.target, "reason": e.reason, "action": e.action,
            "first_seen": iso(e.first_seen), "last_seen": iso(e.last_seen), "blocks": e.blocks,
            "minutes": max(1, round((e.last_seen - e.first_seen).total_seconds() / 60))}


def block_out(b: ProtectionBlock) -> dict:
    return {"id": b.id, "kind": b.kind, "value": b.value, "reason": b.reason, "created_by": b.created_by, "created_at": iso(b.created_at),
            "expires_at": iso(b.expires_at)}


@router.get("")
def overview(actor: Actor = Depends(require("protection.view")), db: Session = Depends(get_db)) -> dict:
    """Blocks in force now on this node, the last day's summary, the operators' blocks and the thresholds."""
    now = utcnow()
    live = protection.current()
    since = now - timedelta(hours=24)
    by_kind = dict(db.execute(select(AttackEvent.kind, func.count()).where(AttackEvent.last_seen >= since).group_by(AttackEvent.kind)).all())
    top = db.execute(select(AttackEvent.target, AttackEvent.kind, func.count(), func.sum(AttackEvent.blocks), func.max(AttackEvent.last_seen))
                     .where(AttackEvent.last_seen >= since).group_by(AttackEvent.target, AttackEvent.kind)
                     .order_by(func.sum(AttackEvent.blocks).desc()).limit(10)).all()
    return {
        "node": get_settings().node_name,
        "now": None if live is None else [
            {"target": t, "kind": kind, "reason": i.get("reason"), "seconds": i.get("seconds"), "blocks": i.get("blocks"), "action": protection.action_of(kind, i)}
            for t, i, kind in ((t, i, protection.kind_of(t, str(i.get("reason") or ""))) for t, i in sorted(live.items(), key=lambda kv: -int(kv[1].get("blocks") or 0)))],
        "day": {"by_kind": by_kind, "top": [{"target": t, "kind": k, "episodes": n, "blocks": int(b or 0), "last_seen": iso(last)} for t, k, n, b, last in top]},
        "blocks": [block_out(b) for b in protection.active_blocks(db)],
        "config": protection.get_config(db),
    }


@router.get("/events")
def events(
    q: str = Query("", max_length=253),
    kind: Kind = "",
    hours: int = Query(24 * 7, ge=1, le=24 * 30),
    paging: Paging = Depends(),
    actor: Actor = Depends(require("protection.view")),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(AttackEvent).where(AttackEvent.last_seen >= utcnow() - timedelta(hours=hours))
    if q:
        stmt = stmt.where(AttackEvent.target.like(like(q.strip())))
    if kind:
        stmt = stmt.where(AttackEvent.kind == kind)
    return paging.apply(db, stmt.order_by(AttackEvent.last_seen.desc(), AttackEvent.id.desc()), event_out)


@router.put("/config")
def set_config(body: dict, background: BackgroundTasks, actor: Actor = Depends(require("protection.manage")), db: Session = Depends(get_db)) -> dict:
    before = protection.get_config(db)
    try:
        after = protection.store_config(db, body)
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    audit.record(db, actor.name, "protection.config_updated", "settings", protection.KEY, {"from": before, "to": after}, actor.ip)
    db.commit()
    background.add_task(runtime.apply_in_background)
    return after


@router.post("/blocks", status_code=201)
def add_block(body: BlockIn, background: BackgroundTasks, actor: Actor = Depends(require("protection.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        value = protection.clean_block(body.kind, body.value)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    if body.kind == "client" and actor.ip and _covers(value, actor.ip):
        raise ApiError(422, "That would block your own address.", {"value": "Your own address is in this network."})
    expires = utcnow() + timedelta(minutes=body.minutes) if body.minutes else None
    existing = db.scalar(select(ProtectionBlock).where(ProtectionBlock.kind == body.kind, ProtectionBlock.value == value))
    if existing is not None:
        # An expired block of the same target comes back with the new reason and duration.
        existing.reason, existing.expires_at, existing.created_by = body.reason.strip(), expires, actor.name
        block = existing
    else:
        block = ProtectionBlock(kind=body.kind, value=value, reason=body.reason.strip(), created_by=actor.name, expires_at=expires)
        db.add(block)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "This is already blocked.") from None
    audit.record(db, actor.name, "protection.block_added", "protection_block", block.id, {"kind": body.kind, "value": value, "reason": block.reason,
                 "minutes": body.minutes}, actor.ip)
    db.commit()
    background.add_task(runtime.apply_in_background)
    return block_out(block)


def _covers(network: str, address: str) -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(network)
    except ValueError:
        return False


@router.delete("/blocks/{block_id}")
def remove_block(block_id: int, background: BackgroundTasks, actor: Actor = Depends(require("protection.manage")), db: Session = Depends(get_db)) -> dict:
    block = db.get(ProtectionBlock, block_id)
    if block is None:
        raise not_found("Block")
    audit.record(db, actor.name, "protection.block_removed", "protection_block", block.id, {"kind": block.kind, "value": block.value}, actor.ip)
    db.delete(block)
    db.commit()
    background.add_task(runtime.apply_in_background)
    return {"ok": True}
