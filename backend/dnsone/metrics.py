"""Prometheus metrics (GET /api/metrics), for an ISP's existing monitoring.

Scrape with an app password (Profile → App passwords, read-only is enough):
    authorization: { type: Bearer, credentials: dnsone_… }
Each node reports itself; scrape every node. DNS counters are the raw dnsdist/Recursor counters
(they reset when the daemon restarts, which Prometheus' rate() handles).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import __version__, alerts, cluster, health, rpz, stats
from .config import Settings, get_settings
from .models import Blocklist, Record, Zone
from .system import utcnow

STATUS = {"ok": 0, "warning": 1, "error": 2}


def _label(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class _Out:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def metric(self, name: str, kind: str, help_: str, samples: list[tuple[dict, float | int | None]]) -> None:
        self.lines += [f"# HELP {name} {help_}", f"# TYPE {name} {kind}"]
        for labels, value in samples:
            if value is None:
                continue
            text = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
            self.lines.append(f"{name}{{{text}}} {value}" if text else f"{name} {value}")


def render(db: Session, settings: Settings | None = None) -> str:
    s = settings or get_settings()
    out = _Out()
    out.metric("dnsone_info", "gauge", "DNSOne version and role of this node.", [({"version": __version__, "node": s.node_name, "role": s.role}, 1)])

    checks = health.checks(db, s)
    out.metric("dnsone_health_status", "gauge", "Health checks: 0 ok, 1 warning, 2 error.",
               [({"check": c["name"]}, STATUS.get(c["status"], 2)) for c in checks])

    states = dict(db.execute(select(Zone.publish_state, func.count()).group_by(Zone.publish_state)).all())
    out.metric("dnsone_zones", "gauge", "Hosted zones by publish state.", [({"state": k}, states.get(k, 0)) for k in ("published", "pending", "error")])
    signing = dict(db.execute(select(Zone.dnssec, func.count()).group_by(Zone.dnssec)).all())
    out.metric("dnsone_zones_dnssec", "gauge", "Hosted zones by DNSSEC signing state.", [({"state": k}, signing.get(k, 0)) for k in ("off", "on", "insecure")])
    out.metric("dnsone_records", "gauge", "Records in all hosted zones.", [({}, db.scalar(select(func.count()).select_from(Record)) or 0)])

    state = rpz.get_state(db, s)
    out.metric("dnsone_rpz_entries", "gauge", "Names in the blocking RPZ of this node.", [({}, int(state.get("entries") or 0))])
    out.metric("dnsone_rpz_build_ok", "gauge", "1 if the last RPZ build succeeded.", [({}, 0 if state.get("state") == "error" else 1)])
    lists = dict(db.execute(select(Blocklist.last_status, func.count()).where(Blocklist.enabled.is_(True)).group_by(Blocklist.last_status)).all())
    out.metric("dnsone_blocklists", "gauge", "Enabled blocklists by the result of their last download.", [({"status": k}, v) for k, v in sorted(lists.items())])

    counters = stats.read_counters(s)
    out.metric("dnsone_dns_events_total", "counter", "DNS counters from dnsdist and the Recursor (reset on daemon restart).",
               [({"event": k}, v) for k, v in counters.items()])

    frontends = health.encrypted_frontends(s) or []
    if frontends:
        try:
            days, _ = health.certificate_days(frontends[0]["address"])
        except (OSError, ValueError):
            days = None
        out.metric("dnsone_tls_certificate_days_left", "gauge", "Days until the DoT/DoH certificate expires.", [({}, days)])

    active = [a for a in alerts.overview(db) if a.get("node") == s.node_name]
    out.metric("dnsone_alerts_active", "gauge", "Problems alerting has open on this node.",
               [({"severity": sev}, sum(1 for a in active if a["severity"] == sev)) for sev in ("error", "warning")])

    now = utcnow()
    seen = []
    for n in cluster.nodes(db):
        try:
            seen.append(({"node": n["node"]}, round((now - datetime.fromisoformat(n["last_seen"])).total_seconds())))
        except (KeyError, ValueError):
            continue
    out.metric("dnsone_node_last_sync_seconds", "gauge", "Seconds since each cluster node last synced.", seen)
    return "\n".join(out.lines) + "\n"
