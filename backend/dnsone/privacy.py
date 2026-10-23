"""Privacy levels for the query log (Settings → Privacy), applied by dnsone-querylog as it stores.

  0  everything: client and domain of every query
  1  hide domains: rows keep the client, the domain is stored as "hidden"; no domain top lists
  2  hide domains and clients: rows keep only time, type, reply and status; no domain or client top lists
  3  anonymous: no query log rows at all; only totals by status, query type and reply code

Retention can be shortened below DNSONE_QUERYLOG_RETENTION_HOURS (the server's maximum), never
lengthened. Rows stored before a level was raised stay as they were until they expire or are erased.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from . import validation
from .config import Settings, get_settings
from .models import Setting

HIDDEN = "hidden"
LEVELS = {
    0: "Show everything",
    1: "Hide domains",
    2: "Hide domains and clients",
    3: "Anonymous: totals only",
}


def get(db: Session, settings: Settings | None = None) -> dict:
    s = settings or get_settings()
    row = db.get(Setting, "querylog.privacy")
    value = dict(row.value) if row else {}
    level = int(value.get("level", 0))
    retention = min(int(value.get("retention_hours") or s.querylog_retention_hours), s.querylog_retention_hours)
    return {"level": level if level in LEVELS else 0, "retention_hours": retention}


def store(db: Session, level: int, retention_hours: int, settings: Settings | None = None) -> dict:
    s = settings or get_settings()
    if level not in LEVELS:
        raise validation.ValidationError("level", "Choose a privacy level.")
    if retention_hours > s.querylog_retention_hours:
        raise validation.ValidationError(
            "retention_hours", f"This server keeps the query log for at most {s.querylog_retention_hours} hours (DNSONE_QUERYLOG_RETENTION_HOURS).")
    value = {"level": level, "retention_hours": retention_hours}
    row = db.get(Setting, "querylog.privacy")
    if row is None:
        db.add(Setting(name="querylog.privacy", value=value))
    else:
        row.value = value
    return value


def describe(db: Session, settings: Settings | None = None) -> dict:
    s = settings or get_settings()
    return {**get(db, s), "levels": [{"level": k, "label": v} for k, v in LEVELS.items()],
            "max_retention_hours": s.querylog_retention_hours, "mode": s.querylog_mode}
