"""Attack protection (Protection page): dnsdist's dynamic blocks, what they caught, and manual blocks.

dnsdist watches the last 10 seconds of traffic (its ring buffers) and blocks by itself (dnsdist.conf,
rules from the settings file runtime.py writes):

  flood             a client above twice its query rate (Settings → DNS server): refused
  servfail          a client causing many SERVFAILs: refused
  nxdomain          a client whose answers are mostly NXDOMAIN: an infected device or CPE sending a
                    random-subdomain attack through the resolver: dropped
  amplification     a client receiving more bytes per second than any real resolver user: answered
                    with TC, so spoofed sources get nothing and real ones retry over TCP
  random-subdomain  a domain asked for with many names that do not exist ("water torture") against
                    its name servers: refused for every client while it lasts. Hosted zones are never
                    blocked this way (BIND answers them itself); their attackers are caught per client.

`dnsone-ctl stats collect` (every minute) stores what dnsdist is blocking as attack_events, so the page
shows the history. Operators add their own blocks (protection_blocks): a client network whose queries
are dropped, or a domain refused for everyone, on every node, until removed or expired.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import timedelta

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import validation
from .config import Settings, get_settings
from .models import AttackEvent, ProtectionBlock, Setting
from .system import utcnow

log = logging.getLogger(__name__)

KEY = "protection.config"
DEFAULTS = {
    "random_subdomain": {"enabled": True, "nxdomains": 500, "names": 200, "seconds": 300},
    # Off by default: ad-blocked names are NXDOMAIN too, so a busy household behind one address can look
    # like an infected device. Turn it on with a threshold above your customers' normal traffic.
    "nxdomain_clients": {"enabled": False, "percent": 80, "responses": 1000, "seconds": 120},
    "amplification": {"enabled": True, "kbytes": 2000, "seconds": 120},
}
LIMITS = {
    ("random_subdomain", "nxdomains"): (10, 10_000_000), ("random_subdomain", "names"): (10, 10_000_000),
    ("random_subdomain", "seconds"): (10, 86400), ("nxdomain_clients", "percent"): (10, 100),
    ("nxdomain_clients", "responses"): (10, 10_000_000), ("nxdomain_clients", "seconds"): (10, 86400),
    ("amplification", "kbytes"): (10, 10_000_000), ("amplification", "seconds"): (10, 86400),
}
# An episode ends when dnsdist has not blocked the target for this long; a new block starts a new one.
EPISODE_GAP = timedelta(minutes=10)
RETENTION = timedelta(days=30)


def get_config(db: Session) -> dict:
    row = db.get(Setting, KEY)
    stored = row.value if row else {}
    return {section: {**defaults, **(stored.get(section) or {})} for section, defaults in DEFAULTS.items()}


def store_config(db: Session, data: dict) -> dict:
    out = {}
    for section, defaults in DEFAULTS.items():
        given = data.get(section) or {}
        if not isinstance(given, dict):
            raise validation.ValidationError(section, "Expected the section's settings.")
        values = {"enabled": bool(given.get("enabled", defaults["enabled"]))}
        for name, default in defaults.items():
            if name == "enabled":
                continue
            low, high = LIMITS[(section, name)]
            try:
                value = int(given.get(name, default))
            except (TypeError, ValueError):
                value = low - 1
            if not low <= value <= high:
                raise validation.ValidationError(f"{section}.{name}", f"Enter a number between {low:,} and {high:,}.")
            values[name] = value
        out[section] = values
    row = db.get(Setting, KEY)
    if row is None:
        db.add(Setting(name=KEY, value=out))
    else:
        row.value = out
    return out


# --------------------------------------------------------------------------- manual blocks


def clean_block(kind: str, raw: str) -> str:
    if kind == "client":
        net = ipaddress.ip_network(validation.network(raw, "value"))
        if net.prefixlen < (8 if net.version == 4 else 32):
            raise validation.ValidationError("value", "That network is too large to block (at most a /8, or a /32 for IPv6).")
        return str(net)
    if kind == "domain":
        name = validation.zone_name(raw, "value")
        if "." not in name:
            raise validation.ValidationError("value", "Block a domain, not a whole top-level domain.")
        return name
    raise validation.ValidationError("kind", "Choose client or domain.")


def active_blocks(db: Session) -> list[ProtectionBlock]:
    now = utcnow()
    return list(db.scalars(select(ProtectionBlock).where((ProtectionBlock.expires_at.is_(None)) | (ProtectionBlock.expires_at > now))
                           .order_by(ProtectionBlock.kind, ProtectionBlock.value)))


def dnsdist_config(db: Session) -> dict:
    """The part of dnsdist's settings file about attacks: thresholds and the operators' blocks."""
    cfg = get_config(db)
    blocks = active_blocks(db)
    rs, nx, amp = cfg["random_subdomain"], cfg["nxdomain_clients"], cfg["amplification"]
    return {
        "random_subdomain": {"nxdomains": rs["nxdomains"], "names": rs["names"], "seconds": rs["seconds"]} if rs["enabled"] else None,
        "nxdomain_clients": {"ratio": nx["percent"] / 100, "responses": nx["responses"], "seconds": nx["seconds"]} if nx["enabled"] else None,
        # dnsdist measures bytes per second over the 10-second window.
        "amplification": {"bytes": amp["kbytes"] * 1000, "seconds": amp["seconds"]} if amp["enabled"] else None,
        "blocked_clients": [b.value for b in blocks if b.kind == "client"],
        "blocked_domains": [b.value for b in blocks if b.kind == "domain"],
    }


# --------------------------------------------------------------------------- what dnsdist blocked


def kind_of(target: str, reason: str) -> str:
    text = reason.lower()
    if "/" not in target:
        return "random-subdomain"
    if "nxdomain" in text:
        return "nxdomain"
    if "byte" in text or "amplification" in text:
        return "amplification"
    if "servfail" in text:
        return "servfail"
    return "flood"


# What the rules do (dnsdist 1.8 reports a dynamic block's Drop as "Unknown").
ACTIONS = {"nxdomain": "Drop", "amplification": "Truncate", "flood": "Refused", "servfail": "Refused", "random-subdomain": "Refused"}


def action_of(kind: str, info: dict) -> str:
    action = str(info.get("action") or "").removeprefix("Send ")
    return ACTIONS.get(kind, "") if action in ("", "Unknown", "None") else action


def current(settings: Settings | None = None) -> dict | None:
    """What this node's dnsdist is blocking now: {target: {reason, seconds, blocks, action}}; None: unreachable."""
    s = settings or get_settings()
    if not s.dnsdist_api_key:
        return None
    try:
        response = httpx.get(f"{s.dnsdist_api_url}/jsonstat", params={"command": "dynblocklist"}, headers={"X-API-Key": s.dnsdist_api_key}, timeout=3)
        response.raise_for_status()
        data = response.json() or {}
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("dnsdist dynamic blocks unavailable: %s", exc)
        return None
    return {target: info or {} for target, info in data.items()} if isinstance(data, dict) else {}


def collect(db: Session, settings: Settings | None = None) -> int:
    """Stores what dnsdist blocks now as attack events. Returns how many targets are blocked."""
    s = settings or get_settings()
    blocks = current(s)
    now = utcnow()
    if blocks:
        recent = {(e.kind, e.target): e for e in db.scalars(select(AttackEvent).where(
            AttackEvent.node == s.node_name, AttackEvent.last_seen >= now - EPISODE_GAP))}
        for target, info in blocks.items():
            reason = str(info.get("reason") or "")[:255]
            kind = kind_of(target, reason)
            count = int(info.get("blocks") or 0)
            event = recent.get((kind, target[:253]))
            if event is None:
                db.add(AttackEvent(node=s.node_name, kind=kind, target=target[:253], reason=reason, action=action_of(kind, info)[:16],
                                   first_seen=now, last_seen=now, blocks=count))
            else:
                event.last_seen = now
                event.blocks = max(event.blocks, count)
    db.execute(delete(AttackEvent).where(AttackEvent.last_seen < now - RETENTION))
    db.execute(delete(ProtectionBlock).where(ProtectionBlock.expires_at.is_not(None), ProtectionBlock.expires_at < now - timedelta(days=1)))
    db.commit()
    return len(blocks or {})


def dnsdist_config_defaults() -> dict:
    """The thresholds without a database (tests rendering the settings file)."""
    rs, nx, amp = DEFAULTS["random_subdomain"], DEFAULTS["nxdomain_clients"], DEFAULTS["amplification"]
    return {"random_subdomain": {"nxdomains": rs["nxdomains"], "names": rs["names"], "seconds": rs["seconds"]},
            "nxdomain_clients": {"ratio": nx["percent"] / 100, "responses": nx["responses"], "seconds": nx["seconds"]},
            "amplification": {"bytes": amp["kbytes"] * 1000, "seconds": amp["seconds"]}, "blocked_clients": [], "blocked_domains": []}
