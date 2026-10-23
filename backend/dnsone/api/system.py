"""Health, statistics, the dashboard and the audit log."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from .. import alerts, health, metrics, rpz, stats
from ..config import get_settings
from ..db import get_db
from .. import __version__
from ..models import AuditLog, Blocklist, RpzRule, User, Zone
from ..security import iso
from .deps import Actor, ApiError, Paging, like, require

router = APIRouter(prefix="/api", tags=["system"])


@router.api_route("/health", methods=["GET", "HEAD"])
def public_health(db: Session = Depends(get_db)) -> dict:
    """Unauthenticated: overall status only (for load balancers and monitoring)."""
    results = health.checks(db, cheap=True)
    status = health.overall(results)
    if status == "error":
        raise ApiError(503, "error")
    return {"status": status}


@router.get("/system/health")
def detailed_health(actor: Actor = Depends(require("dashboard.view")), db: Session = Depends(get_db)) -> dict:
    results = health.checks(db)
    return {"status": health.overall(results), "checks": results}


@router.get("/alerts")
def active_alerts(actor: Actor = Depends(require("dashboard.view")), db: Session = Depends(get_db)) -> dict:
    """Problems alerting has open, on every node (the dashboard banner)."""
    return {"active": alerts.overview(db)}


@router.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics(actor: Actor = Depends(require("dashboard.view")), db: Session = Depends(get_db)) -> PlainTextResponse:
    """Prometheus text format; scrape with an app password as a bearer token."""
    return PlainTextResponse(metrics.render(db), media_type="text/plain; version=0.0.4")


@router.get("/settings/overview")
def settings_overview(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    """Settings → Overview: what this installation is and where its files live."""
    s = get_settings()
    zones = dict(db.execute(select(Zone.status, func.count()).group_by(Zone.status)).all())
    users_total = db.scalar(select(func.count()).select_from(User)) or 0
    users_enabled = db.scalar(select(func.count()).select_from(User).where(User.enabled.is_(True))) or 0
    state = rpz.get_state(db)
    return {
        "usersSummary": {"enabled": users_enabled, "total": users_total},
        "zonesSummary": {"active": zones.get("active", 0), "disabled": zones.get("disabled", 0)},
        "rpzEntries": int(state.get("entries") or 0),
        "rows": [
            ["DNSOne version", __version__],
            ["Node", s.node_name],
            ["Time zone", s.timezone],
            ["Database", f"MySQL {db.scalar(text('SELECT VERSION()'))}"],
            ["Zones", f"{zones.get('active', 0)} active, {zones.get('disabled', 0)} disabled"],
            ["Zone files", str(s.zones_dir)],
            ["BIND include", str(s.bind_zones_conf)],
            ["RPZ file", f"{s.rpz_file} (serial {state.get('serial') or '–'})"],
            ["Log file", str(s.log_file) if s.log_file else "journald only"],
        ],
    }


@router.get("/stats/summary")
def stats_summary(hours: int = Query(24, ge=1, le=24 * 31), actor: Actor = Depends(require("dashboard.view")), db: Session = Depends(get_db)) -> dict:
    return stats.summary(db, hours)


def _fmt(n: int | None) -> str:
    return "–" if n is None else f"{n:,}"


@router.get("/dashboard")
def dashboard(actor: Actor = Depends(require("dashboard.view")), db: Session = Depends(get_db)) -> dict:
    zones = db.scalar(select(func.count()).select_from(Zone)) or 0
    zone_errors = db.scalar(select(func.count()).select_from(Zone).where(Zone.publish_state == "error")) or 0
    lists = db.scalar(select(func.count()).select_from(Blocklist).where(Blocklist.enabled.is_(True))) or 0
    allow = db.scalar(select(func.count()).select_from(RpzRule).where(RpzRule.enabled.is_(True), RpzRule.action == "allow")) or 0
    s = stats.summary(db, 24)
    state = rpz.get_state(db)
    t = s["totals"]
    metrics = [
        {"label": "Queries, 24 h", "value": _fmt(t["queries"]), "icon": "activity", "tone": "", "href": ""},
        {"label": "Blocked, 24 h", "value": _fmt(t["blocked"]) + (f" ({s['block_ratio']}%)" if s["block_ratio"] is not None else ""), "icon": "shield", "tone": "", "href": "/blocking"},
        {"label": "Queries per second", "value": "–" if s["qps"] is None else f"{s['qps']:,}", "icon": "signal", "tone": "", "href": ""},
        {"label": "Cache hit rate", "value": "–" if s["cache_hit_ratio"] is None else f"{s['cache_hit_ratio']}%", "icon": "refresh", "tone": "", "href": ""},
        {"label": "Zones", "value": f"{zones:,}", "icon": "server", "tone": "", "href": "/zones"},
        {"label": "Zones failing to publish", "value": f"{zone_errors:,}", "icon": "logs", "tone": "danger" if zone_errors else "success", "href": "/zones?state=error" if zone_errors else "/zones"},
        {"label": "Blocked domains (RPZ)", "value": f"{int(state.get('entries') or 0):,}", "icon": "shield", "tone": "danger" if state.get("state") == "error" else "", "href": "/blocking"},
        {"label": "Blocklists / allow rules", "value": f"{lists} / {allow}", "icon": "services", "tone": "", "href": "/blocking?tab=blocklists"},
    ]
    recent = db.scalars(select(AuditLog).where(AuditLog.action.not_like("auth.%")).order_by(AuditLog.id.desc()).limit(8)).all()
    return {
        "metrics": metrics,
        "series": s["series"],
        "rpz": state,
        "recent": [{"id": a.id, "actor": a.actor, "action": a.action, "entity": a.entity, "entity_id": a.entity_id, "summary": _summary(a), "created_at": iso(a.created_at)} for a in recent],
    }


def _local_day_start(day: str) -> datetime:
    """Midnight of a YYYY-MM-DD day in DNSONE_TIMEZONE, as naive UTC (like the DATETIME columns)."""
    try:
        zone = ZoneInfo(get_settings().timezone)
    except (ZoneInfoNotFoundError, ValueError):
        zone = timezone.utc
    local = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=zone)
    return local.astimezone(timezone.utc).replace(tzinfo=None)


def _summary(a: AuditLog) -> str:
    p = a.payload_json or {}
    for key in ("name", "zone", "pattern", "username"):
        if key in p and p[key]:
            extra = f" {p['type']} {p.get('value', '')}".rstrip() if key == "zone" and "type" in p else ""
            return f"{p[key]}{extra}"
    return a.entity_id


@router.get("/audit")
def audit_log(
    q: str = Query("", max_length=128),
    actor_name: str = Query("", alias="actor", max_length=64),
    entity: str = Query("", max_length=32),
    action: str = Query("", max_length=64),
    since: str = Query("", alias="from", max_length=10),
    until: str = Query("", alias="to", max_length=10),
    paging: Paging = Depends(),
    actor: Actor = Depends(require("audit.view")),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(AuditLog)
    if q:
        stmt = stmt.where(or_(AuditLog.entity_id == q.strip(), func.json_unquote(AuditLog.payload_json).like(like(q.strip()))))
    if actor_name:
        stmt = stmt.where(AuditLog.actor == actor_name.strip())
    if entity:
        stmt = stmt.where(AuditLog.entity == entity)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action.replace('%', '').replace('_', '')}%"))
    try:
        if since:
            stmt = stmt.where(AuditLog.created_at >= _local_day_start(since))
        if until:
            stmt = stmt.where(AuditLog.created_at < _local_day_start(until) + timedelta(days=1))
    except ValueError:
        raise ApiError(422, "Dates use the form YYYY-MM-DD.", {"from": "Use YYYY-MM-DD."}) from None
    result = paging.apply(db, stmt.order_by(AuditLog.id.desc()), lambda a: {
        "id": a.id, "actor": a.actor, "action": a.action, "entity": a.entity, "entity_id": a.entity_id,
        "payload": a.payload_json, "ip": a.ip, "created_at": iso(a.created_at),
        "summary": _summary(a),
    })
    result["entities"] = sorted(db.scalars(select(AuditLog.entity).distinct()).all())
    result["actors"] = sorted(db.scalars(select(AuditLog.actor).distinct().limit(200)).all())
    return result
