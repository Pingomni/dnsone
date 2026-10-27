"""Nodes (Phase 2): every DNSOne server shares one MySQL and brings itself up to date.

`dnsone-ctl sync` (dnsone-sync.timer, every 30 s) on each node:
  1. writes the runtime files (runtime.apply: dnsdist settings, Recursor ACL and policy data);
  2. zones: the primary publishes zones still pending (edited through another node's console);
     a replica aligns its resolver lists with the zones its BIND secondary receives;
  3. downloads blocklists it has no copy of and rebuilds its RPZ if anything changed;
  4. records a heartbeat (Settings → Cluster lists the nodes from these).

The heartbeat includes the serials the running Recursor and dnsdist report for DNSOne's data, so a
daemon that did not pick up a change (a missing policy script, a stale dnsdist.conf) is visible.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert
from sqlalchemy.orm import Session

from . import __version__, rpz, runtime, stats
from .config import Settings, get_settings
from .db import new_session
from .edition import pro
from .models import Setting, Zone
from .system import utcnow
from .zonegen import Publisher

log = logging.getLogger(__name__)

STALE_MINUTES = 3


def _key(node: str) -> str:
    return f"node.{node}"[:64]


def daemon_serials(settings: Settings | None = None) -> dict:
    """What the running daemons report for DNSOne's generated data (None: unreachable or not loaded)."""
    s = settings or get_settings()
    rec = stats.fetch_statistics(s.recursor_api_url, s.recursor_api_key) or {}
    dist = stats.fetch_statistics(s.dnsdist_api_url, s.dnsdist_api_key) or {}
    return {"recursor_policy": rec.get("dnsone-policy-serial"), "dnsdist_settings": dist.get("dnsone-settings-serial")}


def heartbeat(db: Session, settings: Settings | None = None, messages: list[str] | None = None) -> dict:
    s = settings or get_settings()
    state = rpz.get_state(db, s)
    data = runtime.policy_data(db, s)
    value = {
        "node": s.node_name, "role": s.role, "version": __version__, "last_seen": utcnow().isoformat(timespec="seconds"),
        "rpz": {"serial": state.get("serial"), "state": state.get("state"), "entries": state.get("entries"), "built_revision": state.get("built_revision")},
        "policy_serial": data["serial"],
        "daemons": daemon_serials(s),
        "messages": (messages or [])[-10:],
    }
    # One statement: a sync from the timer and one from the command line (the installer runs both) may
    # write the first heartbeat at the same moment.
    db.execute(insert(Setting).values(name=_key(s.node_name), value=value).on_duplicate_key_update(value=value))
    db.commit()
    return value


def nodes(db: Session) -> list[dict]:
    revision = rpz.get_state(db)["revision"]
    out = []
    for row in db.scalars(select(Setting).where(Setting.name.like("node.%")).order_by(Setting.name)):
        v = dict(row.value)
        try:
            seen = datetime.fromisoformat(v.get("last_seen", ""))
        except ValueError:
            seen = None
        v["stale"] = seen is None or seen < utcnow() - timedelta(minutes=STALE_MINUTES)
        v["rpz_behind"] = int((v.get("rpz") or {}).get("built_revision") or 0) < revision
        out.append(v)
    return out


def sync(settings: Settings | None = None) -> tuple[bool, list[str]]:
    """One synchronisation pass of this node. Returns (ok, what it did)."""
    s = settings or get_settings()
    messages: list[str] = []
    ok = True
    messages += runtime.apply(s)
    publisher = Publisher(s)
    if s.role == "replica":
        good, msg = publisher.replica_sync()
        ok = ok and good
        if msg:
            messages.append(msg)
    else:
        db = new_session()
        try:
            pending = db.scalars(select(Zone.id).where(Zone.publish_state == "pending")).all()
        finally:
            db.close()
        for zone_id in pending:
            result = publisher.publish(zone_id)
            if not result.skipped:
                messages.append(f"{result.zone}: {result.message}")
                ok = ok and result.ok
    db = new_session()
    try:
        firewall = pro("firewall")
        msg = firewall.sync_request(db, s) if firewall else None
    finally:
        db.close()
    if msg:
        messages.append(msg)
    lists = rpz.Blocklists(s)
    for r in lists.fetch_missing():
        messages.append(f"blocklist {r.name}: {r.status} {r.message}")
    result = rpz.RpzBuilder(s).build(only_if_needed=True)
    if result.message != "up to date":
        messages.append(f"RPZ: {result.message}")
    ok = ok and result.ok
    db = new_session()
    try:
        heartbeat(db, s, messages)
    finally:
        db.close()
    return ok, messages


def render_secondary_config(catalog: str, primary: str, port: int) -> str:
    return f"""// DNSOne secondary: follows the primary's catalog zone, so hosted zones appear and disappear by themselves.
// 1. In the options {{ }} block of named.conf.options, add:
//
//    catalog-zones {{
//        zone "{catalog}" default-primaries {{ {primary} port {port}; }} zone-directory "/var/cache/bind/catalog";
//    }};
//
// 2. Add this to named.conf.local, then: mkdir -p /var/cache/bind/catalog && chown bind: /var/cache/bind/catalog
//    && named-checkconf && rndc reconfig
zone "{catalog}" {{
    type secondary;
    primaries {{ {primary} port {port}; }};
    file "/var/cache/bind/{catalog}.db";
}};
"""
