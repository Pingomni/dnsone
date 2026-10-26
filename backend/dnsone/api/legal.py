# SPDX-License-Identifier: Elastic-2.0
# DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
"""Court-ordered blocking: the list, the notice page settings, the export for the regulator, and the
public notice page itself (served on the page's address by deploy/nginx/dnsone-legal.conf)."""

from __future__ import annotations

import csv
import io
from datetime import date
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import audit, legal, rpz, validation
from ..db import get_db
from ..models import LegalBlock
from ..security import iso
from ..system import utcnow
from .deps import Actor, ApiError, Paging, field_error, like, not_found, require

router = APIRouter(prefix="/api/legal", tags=["legal"])


class OrderIn(BaseModel):
    # One name per line ('example.com' blocks it and everything below it; '*.example.com' only below).
    patterns: str = Field(max_length=2_000_000)
    authority: str = Field(min_length=1, max_length=128)
    reference: str = Field(min_length=1, max_length=128)
    ordered_on: date | None = None
    notes: str = Field(default="", max_length=1000)


class LiftIn(BaseModel):
    reason: str = Field(min_length=3, max_length=255)


class LiftOrderIn(LiftIn):
    reference: str = Field(min_length=1, max_length=128)


class PageIn(BaseModel):
    address4: str = Field(default="", max_length=45)
    address6: str = Field(default="", max_length=45)
    title: str = Field(max_length=200)
    message: str = Field(max_length=2000)
    show_reference: bool = True


def block_out(b: LegalBlock) -> dict:
    return {"id": b.id, "pattern": b.pattern, "authority": b.authority, "reference": b.reference,
            "ordered_on": b.ordered_on.isoformat() if b.ordered_on else None, "notes": b.notes, "active": b.active,
            "created_by": b.created_by, "created_at": iso(b.created_at), "lifted_at": iso(b.lifted_at), "lifted_by": b.lifted_by,
            "lift_reason": b.lift_reason}


def _rebuild(db: Session, background: BackgroundTasks) -> None:
    rpz.mark_changed(db)
    background.add_task(rpz.build_in_background)


def _filtered(q: str, status: str, reference: str):
    stmt = select(LegalBlock)
    if q:
        term = like(q.strip().lower())
        stmt = stmt.where(or_(LegalBlock.pattern.like(term), LegalBlock.reference.like(like(q.strip())), LegalBlock.authority.like(like(q.strip()))))
    if status:
        stmt = stmt.where(LegalBlock.active.is_(status == "active"))
    if reference:
        stmt = stmt.where(LegalBlock.reference == reference)
    return stmt


@router.get("")
def list_blocks(
    q: str = Query("", max_length=253),
    status: Literal["", "active", "lifted"] = "active",
    reference: str = Query("", max_length=128),
    paging: Paging = Depends(),
    actor: Actor = Depends(require("legal.view")),
    db: Session = Depends(get_db),
) -> dict:
    result = paging.apply(db, _filtered(q, status, reference).order_by(LegalBlock.active.desc(), LegalBlock.pattern, LegalBlock.id.desc()), block_out)
    state = rpz.get_state(db)
    result["summary"] = {
        "active": db.scalar(select(func.count()).select_from(LegalBlock).where(LegalBlock.active.is_(True))) or 0,
        "orders": db.scalar(select(func.count(LegalBlock.reference.distinct())).where(LegalBlock.active.is_(True))) or 0,
        "triggers": (state.get("groups") or {}).get("legal"),
        "pending": int(state.get("revision") or 0) > int(state.get("built_revision") or 0),
        "page": legal.get_page(db),
    }
    return result


@router.post("", status_code=201)
def add_order(body: OrderIn, background: BackgroundTasks, actor: Actor = Depends(require("legal.manage")), db: Session = Depends(get_db)) -> dict:
    """Adds the names of one order; names already blocked by an active entry are reported, not added twice."""
    patterns, invalid = [], []
    for line in body.patterns.splitlines():
        token = line.split("#", 1)[0].strip()
        if not token:
            continue
        try:
            pattern = validation.rpz_pattern(token, "patterns")
        except validation.ValidationError:
            invalid.append(token[:80])
            continue
        if pattern not in patterns:
            patterns.append(pattern)
    if invalid:
        raise ApiError(422, f"Not a domain: {', '.join(invalid[:10])}{' …' if len(invalid) > 10 else ''}", {"patterns": "Fix or remove the lines that are not domains."})
    if not patterns:
        raise ApiError(422, "Enter at least one domain.", {"patterns": "Enter at least one domain."})
    if len(patterns) > 100_000:
        raise ApiError(422, "Add at most 100,000 names at a time.")
    existing = set()
    for i in range(0, len(patterns), 1000):
        existing |= set(db.scalars(select(LegalBlock.pattern).where(LegalBlock.active.is_(True), LegalBlock.pattern.in_(patterns[i : i + 1000]))))
    new = [p for p in patterns if p not in existing]
    for p in new:
        db.add(LegalBlock(pattern=p, authority=body.authority.strip(), reference=body.reference.strip(), ordered_on=body.ordered_on,
                          notes=body.notes.strip(), active=True, created_by=actor.name))
    if new:
        _rebuild(db, background)
    audit.record(db, actor.name, "legal_block.added", "legal_block", body.reference.strip()[:64], {
        "authority": body.authority.strip(), "reference": body.reference.strip(), "ordered_on": body.ordered_on.isoformat() if body.ordered_on else None,
        "added": len(new), "already_blocked": sorted(existing)[:100], "names": new[:1000]}, actor.ip)
    db.commit()
    return {"added": len(new), "already_blocked": sorted(existing)}


@router.post("/{block_id}/lift")
def lift(block_id: int, body: LiftIn, background: BackgroundTasks, actor: Actor = Depends(require("legal.manage")), db: Session = Depends(get_db)) -> dict:
    block = db.get(LegalBlock, block_id)
    if block is None:
        raise not_found("Entry")
    if not block.active:
        raise ApiError(409, f"{block.pattern} was already lifted on {iso(block.lifted_at)}.")
    block.active, block.lifted_at, block.lifted_by, block.lift_reason = False, utcnow(), actor.name, body.reason.strip()
    _rebuild(db, background)
    audit.record(db, actor.name, "legal_block.lifted", "legal_block", block.id, {"pattern": block.pattern, "reference": block.reference, "reason": block.lift_reason}, actor.ip)
    db.commit()
    return block_out(block)


@router.post("/lift-order")
def lift_order(body: LiftOrderIn, background: BackgroundTasks, actor: Actor = Depends(require("legal.manage")), db: Session = Depends(get_db)) -> dict:
    """Lifts every active entry of one order (e.g. the order was revoked)."""
    rows = list(db.scalars(select(LegalBlock).where(LegalBlock.active.is_(True), LegalBlock.reference == body.reference.strip())))
    if not rows:
        raise ApiError(404, "No active entries have this reference.", {"reference": "No active entries have this reference."})
    now = utcnow()
    for b in rows:
        b.active, b.lifted_at, b.lifted_by, b.lift_reason = False, now, actor.name, body.reason.strip()
    _rebuild(db, background)
    audit.record(db, actor.name, "legal_block.order_lifted", "legal_block", body.reference.strip()[:64],
                 {"reference": body.reference.strip(), "reason": body.reason.strip(), "lifted": len(rows), "names": [b.pattern for b in rows][:1000]}, actor.ip)
    db.commit()
    return {"lifted": len(rows)}


@router.get("/export")
def export(
    q: str = Query("", max_length=253),
    status: Literal["", "active", "lifted"] = "",
    reference: str = Query("", max_length=128),
    actor: Actor = Depends(require("legal.view")),
    db: Session = Depends(get_db),
) -> Response:
    """Every entry (active and lifted) as CSV, e.g. for a report to the regulator."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["domain", "status", "authority", "reference", "ordered_on", "added_at", "added_by", "lifted_at", "lifted_by", "lift_reason", "notes"])
    for b in db.scalars(_filtered(q, status, reference).order_by(LegalBlock.pattern, LegalBlock.id)):
        writer.writerow([b.pattern, "active" if b.active else "lifted", b.authority, b.reference, b.ordered_on or "", iso(b.created_at),
                         b.created_by, iso(b.lifted_at) or "", b.lifted_by or "", b.lift_reason or "", b.notes])
    audit.record(db, actor.name, "legal_block.exported", "legal_block", "", {"status": status or "all", "reference": reference}, actor.ip)
    db.commit()
    name = f"dnsone-court-orders-{utcnow():%Y%m%d}.csv"
    return Response(out.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/page")
def get_page(actor: Actor = Depends(require("legal.view")), db: Session = Depends(get_db)) -> dict:
    return legal.get_page(db)


@router.put("/page")
def set_page(body: PageIn, background: BackgroundTasks, actor: Actor = Depends(require("legal.manage")), db: Session = Depends(get_db)) -> dict:
    before = legal.get_page(db)
    try:
        after = legal.set_page(db, body.model_dump())
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    if (before["address4"], before["address6"]) != (after["address4"], after["address6"]):
        _rebuild(db, background)
    audit.record(db, actor.name, "legal_block.page_updated", "settings", legal.PAGE_KEY, {"changes": {k: {"from": before[k], "to": after[k]}
                 for k in after if before.get(k) != after[k]}}, actor.ip)
    db.commit()
    return after


@router.get("/notice", include_in_schema=False)
def notice(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    """The legal notice page, for any host the list blocks (no sign-in: customers' browsers land here)."""
    host = request.headers.get("host", "")[:253]
    # 451 Unavailable For Legal Reasons (RFC 7725).
    return HTMLResponse(legal.notice_html(db, host), status_code=451, headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex"})
