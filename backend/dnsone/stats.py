"""Query and block statistics from the dnsdist and Recursor HTTP APIs.

`collect()` stores one row of raw counters per minute (dnsone-stats.timer). Totals over a period
are the differences between rows; a counter that went down means the daemon restarted, and the
new value is counted from zero.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .models import StatsSample
from .system import utcnow

log = logging.getLogger(__name__)

FIELDS = ("queries", "blocked", "cache_hits", "cache_misses", "servfail", "dropped")
RETENTION_DAYS = 35


def fetch_statistics(url: str, key: str) -> dict[str, int] | None:
    if not key:
        return None
    try:
        response = httpx.get(f"{url}/api/v1/servers/localhost/statistics", headers={"X-API-Key": key}, timeout=3)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        log.warning("statistics from %s unavailable: %s", url, exc)
        return None
    out: dict[str, int] = {}
    for item in response.json():
        if item.get("type") == "StatisticItem":
            try:
                out[item["name"]] = int(float(item["value"]))
            except (KeyError, TypeError, ValueError):
                continue
    return out


def read_counters(settings: Settings | None = None) -> dict[str, int | None]:
    s = settings or get_settings()
    dist = fetch_statistics(s.dnsdist_api_url, s.dnsdist_api_key)
    rec = fetch_statistics(s.recursor_api_url, s.recursor_api_key)
    blocked = None
    if rec is not None:
        blocked = sum(v for k, v in rec.items() if k.startswith("policy-result-") and k != "policy-result-noaction")
    return {
        "queries": dist.get("queries") if dist else (rec.get("questions") if rec else None),
        "blocked": blocked,
        "cache_hits": rec.get("packetcache-hits") if rec else None,
        "cache_misses": rec.get("packetcache-misses") if rec else None,
        "servfail": dist.get("servfail-responses") if dist else (rec.get("servfail-answers") if rec else None),
        "dropped": (dist.get("rule-drop", 0) + dist.get("dyn-blocked", 0) + dist.get("acl-drops", 0)) if dist else None,
    }


def collect(db: Session, settings: Settings | None = None) -> StatsSample:
    s = settings or get_settings()
    sample = StatsSample(node=s.node_name, sampled_at=utcnow(), **read_counters(s))
    db.add(sample)
    db.execute(delete(StatsSample).where(StatsSample.sampled_at < utcnow() - timedelta(days=RETENTION_DAYS)))
    db.commit()
    return sample


def _increase(rows: list[StatsSample], field: str) -> int | None:
    total, prev, seen = 0, None, False
    for row in rows:
        value = getattr(row, field)
        if value is None:
            continue
        if prev is not None:
            total += value - prev if value >= prev else value
            seen = True
        prev = value
    return total if seen else None


def _floor(t: datetime, step: int) -> datetime:
    """The start of the `step`-minute bucket `t` is in (step divides 60, or is a multiple of it up to a day)."""
    t = t.replace(second=0, microsecond=0)
    return t - timedelta(minutes=(t.hour * 60 + t.minute) % step)


def summary(db: Session, hours: int = 24, step_minutes: int = 60) -> dict:
    """Totals for the period and buckets of `step_minutes` (hourly by default), summed over all nodes."""
    since = utcnow() - timedelta(hours=hours)
    rows = list(db.scalars(select(StatsSample).where(StatsSample.sampled_at >= since - timedelta(minutes=2)).order_by(StatsSample.node, StatsSample.sampled_at)))
    by_node: dict[str, list[StatsSample]] = {}
    for row in rows:
        by_node.setdefault(row.node, []).append(row)

    totals = {f: None for f in FIELDS}
    buckets: dict[datetime, dict[str, int]] = {}
    start = _floor(since, step_minutes)
    for i in range(hours * 60 // step_minutes + 1):
        buckets[start + timedelta(minutes=i * step_minutes)] = {f: 0 for f in FIELDS}
    for node_rows in by_node.values():
        for f in FIELDS:
            inc = _increase(node_rows, f)
            if inc is not None:
                totals[f] = (totals[f] or 0) + inc
        for prev, row in zip(node_rows, node_rows[1:]):
            hour = _floor(row.sampled_at, step_minutes)
            if hour not in buckets:
                continue
            for f in FIELDS:
                a, b = getattr(prev, f), getattr(row, f)
                if a is not None and b is not None:
                    buckets[hour][f] += b - a if b >= a else b

    latest = rows[-1].sampled_at if rows else None
    qps = None
    recent = [r for r in rows if latest and r.sampled_at >= latest - timedelta(minutes=5)]
    if len(recent) >= 2:
        recent_by_node: dict[str, list[StatsSample]] = {}
        for r in recent:
            recent_by_node.setdefault(r.node, []).append(r)
        q = 0.0
        for node_rows in recent_by_node.values():
            inc = _increase(node_rows, "queries")
            span = (node_rows[-1].sampled_at - node_rows[0].sampled_at).total_seconds()
            if inc is not None and span > 0:
                q += inc / span
        qps = round(q, 1)

    queries, blocked = totals["queries"], totals["blocked"]
    hits, misses = totals["cache_hits"], totals["cache_misses"]
    return {
        "hours": hours,
        "nodes": sorted(by_node),
        "sampled_at": latest.isoformat(timespec="seconds") if latest else None,
        "totals": totals,
        "qps": qps,
        "block_ratio": round(100 * blocked / queries, 2) if queries and blocked is not None else None,
        "cache_hit_ratio": round(100 * hits / (hits + misses), 2) if hits is not None and misses is not None and (hits + misses) else None,
        "series": [{"hour": h.isoformat(timespec="minutes"), **v} for h, v in sorted(buckets.items())],
    }
