"""Query visibility: the query log, top lists and breakdowns (written by dnsone-querylog)."""

from __future__ import annotations

from datetime import timedelta
from typing import Literal

import dns.rcode
import dns.rdatatype
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .. import audit, privacy
from ..config import get_settings
from ..db import get_db
from ..models import Setting
from ..querylog import qtype_text, rcode_text
from ..security import iso
from ..system import utcnow
from .deps import Actor, ApiError, like, require

router = APIRouter(prefix="/api/queries", tags=["queries"])

Dimension = Literal["domain", "blocked", "client", "client_blocked", "qtype", "rcode", "status"]


def _ts(value) -> str:
    """Local time with milliseconds."""
    whole = iso(value)
    return f"{whole}.{value.microsecond // 1000:03d}" if whole else ""


@router.get("")
def query_log(
    client: str = Query("", max_length=45),
    qname: str = Query("", max_length=253, description="exact name"),
    domain: str = Query("", max_length=253, description="part of the name; searches the last `minutes`"),
    status: Literal["", "ok", "blocked", "allowed"] = "",
    qtype: str = Query("", max_length=10),
    rcode: str = Query("", max_length=10),
    minutes: int = Query(0, ge=0, le=60 * 24 * 31),
    before: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    actor: Actor = Depends(require("queries.view")),
    db: Session = Depends(get_db),
) -> dict:
    """Newest first, paged by id (`before` = the last id of the previous page), never by COUNT(*)."""
    where, params = [], {}
    if client:
        where.append("client = :client")
        params["client"] = client.strip()
    if qname:
        where.append("qname = :qname")
        params["qname"] = qname.strip().lower().rstrip(".")
    if domain:
        where.append("qname LIKE :domain")
        params["domain"] = like(domain.strip().lower())
        minutes = minutes or 60
    if status:
        where.append("status = :status")
        params["status"] = status
    if qtype:
        try:
            params["qtype"] = int(dns.rdatatype.from_text(qtype.upper()))
        except Exception:  # noqa: BLE001
            raise ApiError(422, "Unknown query type.", {"qtype": "Unknown query type."}) from None
        where.append("qtype = :qtype")
    if rcode:
        try:
            params["rcode"] = int(dns.rcode.from_text(rcode.upper()))
        except Exception:  # noqa: BLE001
            raise ApiError(422, "Unknown reply code.", {"rcode": "Unknown reply code."}) from None
        where.append("rcode = :rcode")
    if minutes:
        where.append("ts >= :since")
        params["since"] = utcnow() - timedelta(minutes=minutes)
    if before:
        where.append("id < :before")
        params["before"] = before
    params["limit"] = limit + 1
    sql = "SELECT id, ts, client, qname, qtype, rcode, status, latency_us FROM query_log"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT :limit"
    rows = db.execute(text(sql), params).all()
    more = len(rows) > limit
    rows = rows[:limit]
    return {
        "rows": [{
            "id": r.id, "time": _ts(r.ts), "client": r.client, "qname": r.qname, "qtype": qtype_text(r.qtype),
            "rcode": rcode_text(r.rcode), "status": r.status, "latency_ms": None if r.latency_us is None else round(r.latency_us / 1000, 1),
        } for r in rows],
        "next_before": rows[-1].id if more and rows else None,
        "window_minutes": minutes or None,
    }


def _since(hours: int):
    return (utcnow() - timedelta(hours=hours)).replace(minute=0, second=0, microsecond=0)


def _top(db: Session, dimension: str, hours: int, limit: int) -> list[dict]:
    rows = db.execute(text(
        "SELECT item, SUM(hits) AS hits FROM query_stats_hourly WHERE dimension = :d AND hour >= :since"
        " GROUP BY item ORDER BY hits DESC, item LIMIT :l"
    ), {"d": dimension, "since": _since(hours), "l": limit}).all()
    return [{"item": r.item, "hits": int(r.hits)} for r in rows]


@router.get("/top")
def top(
    dimension: Dimension = "domain",
    hours: int = Query(24, ge=1, le=24 * 35),
    limit: int = Query(25, ge=1, le=200),
    actor: Actor = Depends(require("queries.view")),
    db: Session = Depends(get_db),
) -> dict:
    return {"dimension": dimension, "hours": hours, "rows": _top(db, dimension, hours, limit)}


@router.get("/summary")
def summary(hours: int = Query(24, ge=1, le=24 * 35), actor: Actor = Depends(require("queries.view")), db: Session = Depends(get_db)) -> dict:
    """Totals by status, query type and reply code, and the collector's state."""
    s = get_settings()
    status = {r["item"]: r["hits"] for r in _top(db, "status", hours, 10)}
    total = sum(status.values())
    collectors = []
    for row in db.scalars(select(Setting).where(Setting.name.like("querylog.state.%"))):
        state = dict(row.value)
        seen = state.get("last_message_at")
        collectors.append({**state, "receiving": bool(seen) and seen >= (utcnow() - timedelta(minutes=5)).isoformat()})
    oldest = db.execute(text("SELECT MIN(ts) FROM query_log")).scalar()
    return {
        "hours": hours,
        "total": total,
        "status": {k: status.get(k, 0) for k in ("ok", "blocked", "allowed")},
        "blocked_ratio": round(100 * status.get("blocked", 0) / total, 2) if total else None,
        "qtype": _top(db, "qtype", hours, 20),
        "rcode": _top(db, "rcode", hours, 20),
        "mode": s.querylog_mode,
        "privacy_level": privacy.get(db)["level"],
        "retention_hours": privacy.get(db)["retention_hours"],
        "max_rows": s.querylog_max_rows,
        "oldest_row": _ts(oldest) if oldest else None,
        "collectors": collectors,
    }


@router.get("/history")
def history(
    days: int = Query(30, ge=1, le=35),
    bucket: Literal["day", "hour"] = "day",
    actor: Actor = Depends(require("queries.view")),
    db: Session = Depends(get_db),
) -> dict:
    """Queries by status per day (or hour) over weeks, from the hourly top-list counters.

    Unlike the query log these counters are kept STATS_RETENTION_DAYS (35) whatever the privacy level.
    """
    since = _since(days * 24)
    rows = db.execute(text(
        "SELECT hour, item, SUM(hits) AS hits FROM query_stats_hourly WHERE dimension = 'status' AND hour >= :since"
        " GROUP BY hour, item ORDER BY hour"
    ), {"since": since}).all()
    series: dict[str, dict[str, int]] = {}
    for r in rows:
        key = r.hour.strftime("%Y-%m-%d") if bucket == "day" else r.hour.strftime("%Y-%m-%d %H:00")
        point = series.setdefault(key, {"ok": 0, "blocked": 0, "allowed": 0})
        point[r.item] = point.get(r.item, 0) + int(r.hits)
    return {"days": days, "bucket": bucket, "timezone": "UTC",
            "series": [{"time": k, "total": sum(v.values()), **v} for k, v in sorted(series.items())]}


@router.delete("")
def erase(
    stats: bool = Query(False, description="also erase the top lists and history"),
    actor: Actor = Depends(require("system.manage")),
    db: Session = Depends(get_db),
) -> dict:
    """Erases the stored query log now (e.g. after raising the privacy level)."""
    rows = 0
    while True:
        deleted = db.execute(text("DELETE FROM query_log LIMIT 50000")).rowcount
        db.commit()
        rows += deleted
        if deleted < 50000:
            break
    counters = db.execute(text("DELETE FROM query_stats_hourly")).rowcount if stats else 0
    audit.record(db, actor.name, "queries.erased", "query_log", "", {"rows": rows, "stats": stats, "counters": counters}, actor.ip)
    db.commit()
    return {"rows": rows, "counters": counters}
