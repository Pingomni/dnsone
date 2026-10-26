"""Settings → Firewall: the configuration, the rules (a draft until applied), Apply and its confirmation."""

from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, firewall, validation
from ..db import get_db
from ..models import FirewallRule
from ..security import iso
from ..system import utcnow
from .deps import Actor, ApiError, field_error, not_found, require

router = APIRouter(prefix="/api/firewall", tags=["firewall"])


class ConfigIn(BaseModel):
    enabled: bool
    management_networks: list[str] = Field(default_factory=list, max_length=200)
    dns: bool = True
    dot: bool = False
    doh: bool = False


class RuleIn(BaseModel):
    action: Literal["accept", "drop", "reject"]
    protocol: Literal["tcp", "udp", "tcp+udp", "icmp", "any"] = "tcp"
    source: str = Field(default="", max_length=49)
    ports: str = Field(default="", max_length=64)
    comment: str = Field(default="", max_length=255)
    enabled: bool = True
    # 0: permanent.
    minutes: int = Field(default=0, ge=0, le=525600)


class RulePatch(BaseModel):
    enabled: bool | None = None
    comment: str | None = Field(default=None, max_length=255)
    # Moves the rule up (-1) or down (+1).
    move: Literal[-1, 1] | None = None


class ConfirmIn(BaseModel):
    id: str = Field(max_length=32)


def rule_out(r: FirewallRule) -> dict:
    return {"id": r.id, "position": r.position, "action": r.action, "protocol": r.protocol, "source": r.source, "ports": r.ports,
            "comment": r.comment, "enabled": r.enabled, "created_by": r.created_by, "created_at": iso(r.created_at),
            "expires_at": iso(r.expires_at), "expired": bool(r.expires_at and r.expires_at <= utcnow())}


def _inside(address: str, networks: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_loopback or any(ip in ipaddress.ip_network(n) for n in networks)


def _state(db: Session, actor: Actor) -> dict:
    current = firewall.draft(db)
    live = firewall.active(db)
    try:
        preview = firewall.render(current)
    except firewall.FirewallError as exc:
        preview = f"# cannot render: {exc}"
    pending = live is None or {k: live.get(k) for k in ("config", "rules", "secondaries")} != current
    cfg = current["config"]
    warnings = []
    st = firewall.status()
    if cfg["enabled"] and not _inside(actor.ip, cfg["management_networks"]):
        warnings.append(f"Your address {actor.ip} is not in the management networks: you would lose the console once the firewall is on.")
    if st.get("ufw_active"):
        warnings.append("ufw is active on this server too: its rules still apply on top of DNSOne's. Once DNSOne's firewall works, turn ufw off (sudo ufw disable).")
    if cfg["enabled"] and not cfg["dns"]:
        warnings.append("DNS (port 53) is closed: customers and the internet cannot reach the resolver or the hosted zones.")
    if cfg["doh"]:
        warnings.append("DNS over HTTPS opens port 443 to everyone, and with it the console's sign-in page.")
    return {
        "config": cfg,
        "rules": [rule_out(r) for r in firewall.rules(db)],
        "secondaries": current["secondaries"],
        "active": {"id": live.get("id"), "by": live.get("by"), "at": live.get("at"), "enabled": (live.get("config") or {}).get("enabled")} if live else None,
        "pending": pending,
        "status": st,
        "preview": preview,
        "warnings": warnings,
        "client_ip": actor.ip,
        "can_apply": firewall.can_apply(),
        "confirm_seconds": firewall.CONFIRM_SECONDS,
    }


@router.get("")
def overview(actor: Actor = Depends(require("firewall.manage")), db: Session = Depends(get_db)) -> dict:
    return _state(db, actor)


@router.get("/status")
def apply_status(actor: Actor = Depends(require("firewall.manage"))) -> dict:
    return firewall.status()


@router.put("/config")
def set_config(body: ConfigIn, actor: Actor = Depends(require("firewall.manage")), db: Session = Depends(get_db)) -> dict:
    before = firewall.get_config(db)
    try:
        after = firewall.store_config(db, body.model_dump())
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    audit.record(db, actor.name, "firewall.config_updated", "settings", firewall.CONFIG_KEY, {"from": before, "to": after}, actor.ip)
    db.commit()
    return _state(db, actor)


@router.post("/rules", status_code=201)
def add_rule(body: RuleIn, actor: Actor = Depends(require("firewall.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        clean = firewall.clean_rule(body.model_dump())
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    if db.scalar(select(func.count()).select_from(FirewallRule)) >= firewall.MAX_RULES:
        raise ApiError(422, f"At most {firewall.MAX_RULES} rules.")
    if clean["action"] != "accept" and clean["source"] and actor.ip and _inside(actor.ip, [clean["source"]]) and not ipaddress.ip_address(actor.ip).is_loopback:
        raise ApiError(422, "This rule would block your own address.", {"source": f"Your address {actor.ip} is in this network."})
    last = db.scalar(select(func.max(FirewallRule.position))) or 0
    rule = FirewallRule(**clean, position=last + 1, comment=body.comment.strip(), enabled=body.enabled, created_by=actor.name,
                        expires_at=utcnow() + timedelta(minutes=body.minutes) if body.minutes else None)
    db.add(rule)
    db.flush()
    audit.record(db, actor.name, "firewall.rule_added", "firewall_rule", rule.id, {**clean, "comment": rule.comment, "minutes": body.minutes}, actor.ip)
    db.commit()
    return rule_out(rule)


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: int, body: RulePatch, actor: Actor = Depends(require("firewall.manage")), db: Session = Depends(get_db)) -> dict:
    rule = db.get(FirewallRule, rule_id)
    if rule is None:
        raise not_found("Rule")
    changes: dict = {}
    if body.enabled is not None and body.enabled != rule.enabled:
        rule.enabled = body.enabled
        changes["enabled"] = body.enabled
    if body.comment is not None:
        rule.comment = body.comment.strip()
        changes["comment"] = rule.comment
    if body.move is not None:
        ordered = firewall.rules(db)
        i = next(i for i, r in enumerate(ordered) if r.id == rule.id)
        j = i + body.move
        if 0 <= j < len(ordered):
            ordered[i], ordered[j] = ordered[j], ordered[i]
            for pos, r in enumerate(ordered, start=1):
                r.position = pos
            changes["position"] = j + 1
    if changes:
        audit.record(db, actor.name, "firewall.rule_updated", "firewall_rule", rule.id, {"changes": changes}, actor.ip)
    db.commit()
    return rule_out(rule)


@router.delete("/rules/{rule_id}")
def delete_rule(rule_id: int, actor: Actor = Depends(require("firewall.manage")), db: Session = Depends(get_db)) -> dict:
    rule = db.get(FirewallRule, rule_id)
    if rule is None:
        raise not_found("Rule")
    audit.record(db, actor.name, "firewall.rule_deleted", "firewall_rule", rule.id, {k: getattr(rule, k) for k in ("action", "protocol", "source", "ports", "comment")}, actor.ip)
    db.delete(rule)
    db.commit()
    return {"ok": True}


@router.post("/apply")
def apply(actor: Actor = Depends(require("firewall.manage")), db: Session = Depends(get_db)) -> dict:
    """Puts the draft live on this node (and, through sync, the others): the console must confirm within a minute."""
    cfg = firewall.get_config(db)
    if cfg["enabled"] and not _inside(actor.ip, cfg["management_networks"]):
        raise ApiError(422, f"Your address {actor.ip} is not in the management networks: add it first, or you would lose the console.",
                       {"management_networks": f"Add {actor.ip} (or its network)."})
    try:
        snapshot = firewall.request_apply(db, actor.name)
    except firewall.FirewallError as exc:
        raise ApiError(409, str(exc)) from None
    audit.record(db, actor.name, "firewall.applied", "settings", firewall.ACTIVE_KEY, {"id": snapshot["id"], "enabled": snapshot["config"]["enabled"],
                 "rules": len(snapshot["rules"])}, actor.ip)
    db.commit()
    return {"id": snapshot["id"], "message": "Applying; the console confirms it can still reach the server."}


@router.post("/confirm")
def confirm(body: ConfirmIn, actor: Actor = Depends(require("firewall.manage"))) -> dict:
    """Sent by the console once it sees the new rules in force: proof it can still reach the server."""
    if not firewall.confirm(body.id):
        raise ApiError(409, "Nothing is waiting for a confirmation (it may have been rolled back already).")
    return {"ok": True}
