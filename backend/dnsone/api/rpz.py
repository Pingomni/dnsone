"""Ad-blocking: rules (exact names and regexes, for every group or one), blocklists and allowlists,
the block policy, pausing, and the RPZ build."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, rpz, runtime, validation
from ..db import get_db
from ..models import Blocklist, ClientGroup, RpzRule
from ..security import iso
from .deps import Actor, ApiError, Paging, field_error, like, not_found, require

router = APIRouter(prefix="/api/rpz", tags=["rpz"])

RuleAction = Literal["block", "allow", "nxdomain", "nodata", "redirect"]


class RuleIn(BaseModel):
    pattern: str = Field(max_length=253)
    match_type: Literal["exact", "regex"] = "exact"
    action: RuleAction
    target: str | None = Field(default=None, max_length=253)
    # None: every group.
    group_id: int | None = None
    enabled: bool = True
    comment: str = Field(default="", max_length=255)


class RulePatch(BaseModel):
    action: RuleAction | None = None
    target: str | None = Field(default=None, max_length=253)
    enabled: bool | None = None
    comment: str | None = Field(default=None, max_length=255)


class RuleImport(BaseModel):
    action: Literal["block", "allow"]
    text: str = Field(max_length=2_000_000)
    group_id: int | None = None
    comment: str = Field(default="", max_length=255)


class BlocklistIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(max_length=2048)
    format: Literal["auto", "hosts", "domains", "adblock"] = "auto"
    # allow: an allowlist subscription.
    kind: Literal["block", "allow"] = "block"
    enabled: bool = True
    # None: the Default group.
    group_ids: list[int] | None = None


class BlocklistPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    url: str | None = Field(default=None, max_length=2048)
    format: Literal["auto", "hosts", "domains", "adblock"] | None = None
    enabled: bool | None = None
    group_ids: list[int] | None = None


class PauseIn(BaseModel):
    # 0: until resumed.
    minutes: int = Field(ge=0, le=7 * 24 * 60)
    group_id: int | None = None


class PolicyIn(BaseModel):
    action: Literal["nxdomain", "nodata", "null_ip", "walled_garden"]
    walled_garden_target: str = Field(default="", max_length=253)
    block_subdomains: bool = True


def rule_out(r: RpzRule, groups: dict[int, str] | None = None) -> dict:
    return {"id": r.id, "pattern": r.pattern, "match_type": r.match_type, "action": r.action, "target": r.target,
            "group_id": r.group_id, "group": (groups or {}).get(r.group_id) if r.group_id else None, "source": r.source, "enabled": r.enabled,
            "comment": r.comment, "created_by": r.created_by, "created_at": iso(r.created_at), "updated_at": iso(r.updated_at)}


def blocklist_out(b: Blocklist) -> dict:
    return {"id": b.id, "name": b.name, "url": b.url, "format": b.format, "kind": b.kind, "enabled": b.enabled, "last_updated": iso(b.last_updated),
            "last_checked": iso(b.last_checked), "last_status": b.last_status, "last_error": b.last_error, "domain_count": b.domain_count,
            "groups": [{"id": g.id, "name": g.name} for g in sorted(b.groups, key=lambda g: (not g.built_in, g.name))]}


def _group_names(db: Session) -> dict[int, str]:
    return dict(db.execute(select(ClientGroup.id, ClientGroup.name)).all())


def _groups(db: Session, ids: list[int] | None, field: str = "group_ids") -> list[ClientGroup]:
    if ids is None:
        return [db.scalar(select(ClientGroup).where(ClientGroup.built_in.is_(True)))]
    groups = list(db.scalars(select(ClientGroup).where(ClientGroup.id.in_(ids)))) if ids else []
    if len(groups) != len(set(ids)):
        raise validation.ValidationError(field, "One of the chosen groups no longer exists.")
    return groups


def _group(db: Session, group_id: int | None) -> ClientGroup | None:
    if group_id is None:
        return None
    group = db.get(ClientGroup, group_id)
    if group is None:
        raise validation.ValidationError("group_id", "This group no longer exists.")
    return group


def _pattern(match_type: str, action: str, raw: str) -> str:
    if match_type == "regex":
        if action not in ("block", "allow"):
            raise validation.ValidationError("action", "Regex rules block or allow; choose one of those.")
        return validation.regex_pattern(raw)
    return validation.rpz_pattern(raw)


def _changed(db: Session, background: BackgroundTasks, regex: bool) -> None:
    """After a change to rules or lists: regex rules live in the runtime files, the rest in the RPZ."""
    if regex:
        background.add_task(runtime.apply_in_background)
    else:
        rpz.mark_changed(db)


def _target(action: str, target: str | None) -> str | None:
    if action != "redirect":
        return None
    return validation.walled_garden_target(target or "", "target")


def _url(raw: str) -> str:
    url = raw.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise validation.ValidationError("url", "Enter an http:// or https:// address.")
    return url


# --------------------------------------------------------------------------- status and policy


def _pause_out(db: Session) -> dict:
    pause = runtime.get_pause(db)
    names = _group_names(db)

    def until(epoch: int | None) -> str | None:
        if epoch is None:
            return None
        return "forever" if epoch >= runtime.FOREVER else iso(datetime.fromtimestamp(epoch, timezone.utc).replace(tzinfo=None))

    return {"all": until(pause["all"]), "groups": [{"id": gid, "name": names.get(gid, "?"), "until": until(v)} for gid, v in sorted(pause["groups"].items())]}


@router.get("/status")
def status(actor: Actor = Depends(require("rpz.view")), db: Session = Depends(get_db)) -> dict:
    state = rpz.get_state(db)
    state["pending"] = int(state.get("revision") or 0) > int(state.get("built_revision") or 0)
    return {"state": state, "policy": rpz.get_policy(db), "pause": _pause_out(db)}


@router.post("/pause")
def pause(body: PauseIn, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    """Pauses blocking for everyone or one group, for N minutes (0: until resumed)."""
    try:
        group = _group(db, body.group_id)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    runtime.set_pause(db, body.group_id, body.minutes)
    audit.record(db, actor.name, "rpz.paused", "rpz", body.group_id or "", {"name": group.name if group else "everyone", "minutes": body.minutes or "until resumed"}, actor.ip)
    db.commit()
    background.add_task(runtime.apply_in_background)
    return _pause_out(db)


@router.delete("/pause")
def resume(background: BackgroundTasks, group_id: int | None = Query(None), actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    """Resumes blocking for one group, or for everyone and every group."""
    runtime.resume(db, group_id)
    names = _group_names(db)
    audit.record(db, actor.name, "rpz.resumed", "rpz", group_id or "", {"name": names.get(group_id, "?") if group_id else "everyone"}, actor.ip)
    db.commit()
    background.add_task(runtime.apply_in_background)
    return _pause_out(db)


@router.put("/policy")
def set_policy(body: PolicyIn, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    before = rpz.get_policy(db)
    try:
        value = rpz.set_policy(db, body.action, body.walled_garden_target, body.block_subdomains)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    rpz.mark_changed(db)
    audit.record(db, actor.name, "rpz.policy_updated", "rpz_policy", "", {"from": before, "to": value}, actor.ip)
    db.commit()
    background.add_task(rpz.build_in_background)
    return value


@router.post("/build")
def build(actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    audit.record(db, actor.name, "rpz.build_requested", "rpz", "", None, actor.ip)
    db.commit()
    try:
        result = rpz.RpzBuilder().build()
    except TimeoutError as exc:
        raise ApiError(409, str(exc)) from None
    if not result.ok:
        raise ApiError(422, result.message)
    return {"serial": result.serial, "entries": result.entries, "message": result.message}


@router.get("/lookup")
def lookup(domain: str = Query(max_length=253), group_id: int | None = Query(None), actor: Actor = Depends(require("rpz.view")), db: Session = Depends(get_db)) -> dict:
    try:
        return rpz.lookup(db, domain, group_id)
    except validation.ValidationError as exc:
        raise field_error(exc) from None


# --------------------------------------------------------------------------- rules


@router.get("/rules")
def list_rules(
    q: str = Query("", max_length=253),
    action: Literal["", "block", "allow", "nxdomain", "nodata", "redirect"] = "",
    enabled: Literal["", "1", "0"] = "",
    match_type: Literal["", "exact", "regex"] = "",
    group: str = Query("", max_length=10, description="'' any, 'all' rules for every group, or a group id"),
    paging: Paging = Depends(),
    actor: Actor = Depends(require("rpz.view")),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(RpzRule)
    if q:
        stmt = stmt.where(or_(RpzRule.pattern.like(like(q.strip().lower())), RpzRule.comment.like(like(q.strip()))))
    if action:
        stmt = stmt.where(RpzRule.action == action)
    if enabled:
        stmt = stmt.where(RpzRule.enabled.is_(enabled == "1"))
    if match_type:
        stmt = stmt.where(RpzRule.match_type == match_type)
    if group == "all":
        stmt = stmt.where(RpzRule.group_id.is_(None))
    elif group.isdigit():
        stmt = stmt.where(RpzRule.group_id == int(group))
    names = _group_names(db)
    return paging.apply(db, stmt.order_by(RpzRule.pattern, RpzRule.group_key), lambda r: rule_out(r, names))


@router.post("/rules", status_code=201)
def create_rule(body: RuleIn, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        pattern = _pattern(body.match_type, body.action, body.pattern)
        target = _target(body.action, body.target)
        group = _group(db, body.group_id)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    rule = RpzRule(pattern=pattern, match_type=body.match_type, action=body.action, target=target, group_id=body.group_id,
                   enabled=body.enabled, comment=body.comment.strip(), source="manual", created_by=actor.name)
    db.add(rule)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        where = f" for group {group.name}" if group else ""
        raise ApiError(409, f"There is already a rule for {pattern}{where}.", {"pattern": "A rule for this pattern already exists."}) from None
    _changed(db, background, body.match_type == "regex")
    audit.record(db, actor.name, "rpz_rule.created", "rpz_rule", rule.id, {"pattern": pattern, "match_type": body.match_type, "action": body.action,
                 "target": target, "group": group.name if group else "all"}, actor.ip)
    db.commit()
    if body.match_type == "exact":
        background.add_task(rpz.build_in_background)
    return rule_out(rule, _group_names(db))


@router.post("/rules/import")
def import_rules(body: RuleImport, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    """Adds one rule per line (domain or *.domain); existing patterns are left as they are."""
    patterns, invalid = set(), []
    for line in body.text.splitlines():
        token = line.split("#", 1)[0].strip()
        if not token:
            continue
        try:
            patterns.add(validation.rpz_pattern(token))
        except validation.ValidationError:
            invalid.append(token[:80])
    if len(patterns) > 50000:
        raise ApiError(422, "Import at most 50,000 domains at a time; use a blocklist for larger lists.")
    try:
        _group(db, body.group_id)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    existing = set()
    pattern_list = sorted(patterns)
    for i in range(0, len(pattern_list), 1000):
        existing |= set(db.scalars(select(RpzRule.pattern).where(RpzRule.pattern.in_(pattern_list[i : i + 1000]), RpzRule.group_key == (body.group_id or 0))))
    new = [p for p in pattern_list if p not in existing]
    for p in new:
        db.add(RpzRule(pattern=p, action=body.action, group_id=body.group_id, enabled=True, comment=body.comment.strip(), source="import", created_by=actor.name))
    if new:
        rpz.mark_changed(db)
    audit.record(db, actor.name, "rpz_rule.imported", "rpz_rule", "", {"action": body.action, "added": len(new), "skipped_existing": len(existing), "invalid": len(invalid)}, actor.ip)
    db.commit()
    if new:
        background.add_task(rpz.build_in_background)
    return {"added": len(new), "existing": len(existing), "invalid": invalid[:50], "invalid_count": len(invalid)}


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: int, body: RulePatch, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    rule = db.get(RpzRule, rule_id)
    if rule is None:
        raise not_found("Rule")
    before = rule_out(rule)
    try:
        action = body.action or rule.action
        if rule.match_type == "regex" and action not in ("block", "allow"):
            raise validation.ValidationError("action", "Regex rules block or allow; choose one of those.")
        target = _target(action, body.target if body.target is not None else rule.target)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    rule.action, rule.target = action, target
    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.comment is not None:
        rule.comment = body.comment.strip()
    regex = rule.match_type == "regex"
    _changed(db, background, regex)
    names = _group_names(db)
    after = rule_out(rule, names)
    diff = {k: {"from": before[k], "to": after[k]} for k in ("action", "target", "enabled", "comment") if before[k] != after[k]}
    audit.record(db, actor.name, "rpz_rule.updated", "rpz_rule", rule.id, {"pattern": rule.pattern, "changes": diff}, actor.ip)
    db.commit()
    if not regex:
        background.add_task(rpz.build_in_background)
    return after


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    rule = db.get(RpzRule, rule_id)
    if rule is None:
        raise not_found("Rule")
    audit.record(db, actor.name, "rpz_rule.deleted", "rpz_rule", rule.id, {"pattern": rule.pattern, "action": rule.action}, actor.ip)
    regex = rule.match_type == "regex"
    db.delete(rule)
    _changed(db, background, regex)
    db.commit()
    if not regex:
        background.add_task(rpz.build_in_background)
    return {"ok": True}


# --------------------------------------------------------------------------- blocklists


@router.get("/blocklists")
def list_blocklists(
    q: str = Query("", max_length=128),
    status: Literal["", "never", "ok", "not_modified", "error"] = "",
    kind: Literal["", "block", "allow"] = "",
    paging: Paging = Depends(),
    actor: Actor = Depends(require("rpz.view")),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(Blocklist)
    if q:
        stmt = stmt.where(or_(Blocklist.name.like(like(q.strip())), Blocklist.url.like(like(q.strip()))))
    if status:
        stmt = stmt.where(Blocklist.last_status == status)
    if kind:
        stmt = stmt.where(Blocklist.kind == kind)
    return paging.apply(db, stmt.order_by(Blocklist.name), blocklist_out)


@router.post("/blocklists", status_code=201)
def create_blocklist(body: BlocklistIn, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        url = _url(body.url)
        groups = _groups(db, body.group_ids)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    bl = Blocklist(name=body.name.strip(), url=url, format=body.format, kind=body.kind, enabled=body.enabled, groups=groups)
    db.add(bl)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "A blocklist with this name already exists.", {"name": "This name is taken."}) from None
    audit.record(db, actor.name, "blocklist.created", "blocklist", bl.id, {"name": bl.name, "url": url, "format": bl.format, "kind": bl.kind,
                 "groups": [g.name for g in groups]}, actor.ip)
    db.commit()
    if bl.enabled:
        background.add_task(rpz.refresh_in_background, bl.id)
    return blocklist_out(bl)


@router.patch("/blocklists/{blocklist_id}")
def update_blocklist(blocklist_id: int, body: BlocklistPatch, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    bl = db.get(Blocklist, blocklist_id)
    if bl is None:
        raise not_found("Blocklist")
    before = blocklist_out(bl)
    refetch = False
    try:
        if body.name is not None:
            bl.name = body.name.strip()
        if body.url is not None and body.url.strip() != bl.url:
            bl.url = _url(body.url)
            refetch = True
        if body.format is not None and body.format != bl.format:
            bl.format = body.format
            refetch = True
        if body.enabled is not None:
            refetch = refetch or (body.enabled and bl.last_status == "never")
            bl.enabled = body.enabled
        if body.group_ids is not None:
            bl.groups = _groups(db, body.group_ids)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    rpz.mark_changed(db)
    after = blocklist_out(bl)
    diff = {k: {"from": before[k], "to": after[k]} for k in ("name", "url", "format", "enabled", "groups") if before[k] != after[k]}
    audit.record(db, actor.name, "blocklist.updated", "blocklist", bl.id, {"name": bl.name, "changes": diff}, actor.ip)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "A blocklist with this name already exists.", {"name": "This name is taken."}) from None
    if refetch and bl.enabled:
        background.add_task(rpz.refresh_in_background, bl.id)
    else:
        background.add_task(rpz.build_in_background)
    return after


@router.post("/blocklists/{blocklist_id}/refresh")
def refresh_blocklist(blocklist_id: int, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    bl = db.get(Blocklist, blocklist_id)
    if bl is None:
        raise not_found("Blocklist")
    audit.record(db, actor.name, "blocklist.refresh_requested", "blocklist", bl.id, {"name": bl.name}, actor.ip)
    db.commit()
    result = rpz.Blocklists().refresh(bl.id, force=True)
    db.expire_all()
    if result.status == "ok":
        rpz.mark_changed(db)
        db.commit()
        background.add_task(rpz.build_in_background)
    bl = db.get(Blocklist, blocklist_id)
    if result.status == "error":
        raise ApiError(422, result.message)
    return {**blocklist_out(bl), "message": result.message}


@router.delete("/blocklists/{blocklist_id}")
def delete_blocklist(blocklist_id: int, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    bl = db.get(Blocklist, blocklist_id)
    if bl is None:
        raise not_found("Blocklist")
    audit.record(db, actor.name, "blocklist.deleted", "blocklist", bl.id, {"name": bl.name, "url": bl.url}, actor.ip)
    db.delete(bl)
    rpz.mark_changed(db)
    db.commit()
    rpz.Blocklists().path(blocklist_id).unlink(missing_ok=True)
    background.add_task(rpz.build_in_background)
    return {"ok": True}
