"""Audit trail: one row per write, added in the same transaction as the change it records."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from .models import AuditLog

log = logging.getLogger("dnsone.audit")

_SECRET_KEYS = {"password", "new_password", "current_password", "password_hash", "smtp_password", "bot_token"}


def _scrub(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("***" if k in _SECRET_KEYS else _scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def record(db: Session, actor: str, action: str, entity: str, entity_id: Any = "", payload: dict | None = None, ip: str = "") -> None:
    clean = _scrub(payload) if payload is not None else None
    db.add(AuditLog(actor=actor[:64], action=action[:64], entity=entity[:32], entity_id=str(entity_id)[:64], payload_json=clean, ip=ip[:45]))
    log.info("audit actor=%s action=%s entity=%s id=%s", actor, action, entity, entity_id)
