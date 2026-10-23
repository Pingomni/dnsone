"""Alerts: tell the operators when something breaks, instead of waiting for customers to call.

`dnsone-ctl alerts check` (run every minute by dnsone-stats.service, on every node) evaluates:
- every health check (health.checks) that is not ok: BIND, Recursor, dnsdist, query log, disks,
  the data the daemons run, the TLS certificate of DoT/DoH, ...;
- blocklists whose last download failed;
- addresses dnsdist is blocking for query floods (dynamic blocks).

An alert is sent once it has lasted `for_minutes` (so a reload or a single slow probe stays quiet),
repeated every `repeat_hours` while it lasts, and followed by a "resolved" message. Checks about
the shared data (zone publishing, blocklists, cluster) run on the primary only, so a cluster does not
send them once per node; the others are per node and name the node.

Channels (Settings → Alerts): email (SMTP), a webhook (JSON with a "text" field, which Slack,
Mattermost, Rocket.Chat and Teams incoming webhooks accept) and Telegram (bot token + chat id).
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
from datetime import datetime, timedelta
from email.message import EmailMessage

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import health, validation
from .config import Settings, get_settings
from .models import Blocklist, Setting
from .system import utcnow

log = logging.getLogger(__name__)

CONFIG_KEY = "alerts.config"
SECRETS = (("email", "smtp_password"), ("telegram", "bot_token"))
# Checks about data every node shares: alerted by the primary only.
SHARED_CHECKS = {"Zone publishing", "Cluster"}
TIMEOUT = 10

DEFAULTS: dict = {
    "enabled": False,
    "for_minutes": 2,
    "repeat_hours": 6,
    "warnings": True,
    "email": {"enabled": False, "to": [], "from": "", "smtp_host": "", "smtp_port": 587, "smtp_security": "starttls",
              "smtp_user": "", "smtp_password": ""},
    "webhook": {"enabled": False, "url": ""},
    "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
}


def _state_key(node: str) -> str:
    return f"alerts.state.{node}"[:64]


def get_config(db: Session) -> dict:
    row = db.get(Setting, CONFIG_KEY)
    stored = row.value if row else {}
    out = json.loads(json.dumps(DEFAULTS))
    for key, value in stored.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key].update(value)
        else:
            out[key] = value
    return out


def public_config(db: Session) -> dict:
    return public_config_from(get_config(db))


def public_config_from(cfg: dict) -> dict:
    """The configuration for the console: secrets replaced by whether they are set."""
    out = json.loads(json.dumps(cfg))
    for section, key in SECRETS:
        out[section][f"{key}_set"] = bool(out[section][key])
        out[section][key] = ""
    return out


def _url(raw: str, field: str) -> str:
    value = raw.strip()
    if not value:
        raise validation.ValidationError(field, "Enter the webhook URL.")
    if not value.startswith(("https://", "http://")) or len(value) > 2048 or any(c.isspace() for c in value):
        raise validation.ValidationError(field, "Enter an http(s) URL, e.g. https://hooks.slack.com/services/…")
    return value


def store_config(db: Session, data: dict) -> dict:
    """Validates and saves Settings → Alerts. An empty secret keeps the stored one."""
    old = get_config(db)
    cfg = json.loads(json.dumps(DEFAULTS))
    cfg["enabled"] = bool(data.get("enabled"))
    cfg["warnings"] = bool(data.get("warnings", True))
    try:
        cfg["for_minutes"] = int(data.get("for_minutes", 2))
        cfg["repeat_hours"] = int(data.get("repeat_hours", 6))
    except (TypeError, ValueError):
        raise validation.ValidationError("for_minutes", "Enter whole numbers.") from None
    if not 1 <= cfg["for_minutes"] <= 60:
        raise validation.ValidationError("for_minutes", "Between 1 and 60 minutes.")
    if not 0 <= cfg["repeat_hours"] <= 168:
        raise validation.ValidationError("repeat_hours", "Between 0 (never repeat) and 168 hours.")

    email = data.get("email") or {}
    e = cfg["email"]
    e["enabled"] = bool(email.get("enabled"))
    e["to"] = [validation.email(str(a)) for a in (email.get("to") or []) if str(a).strip()][:20]
    e["from"] = validation.email(str(email.get("from") or ""))
    e["smtp_host"] = str(email.get("smtp_host") or "").strip()[:253]
    e["smtp_port"] = int(email.get("smtp_port") or 587)
    e["smtp_security"] = email.get("smtp_security") if email.get("smtp_security") in ("starttls", "tls", "none") else "starttls"
    e["smtp_user"] = str(email.get("smtp_user") or "").strip()[:254]
    e["smtp_password"] = str(email.get("smtp_password") or "") or old["email"]["smtp_password"]
    if e["enabled"]:
        if not e["to"]:
            raise validation.ValidationError("email.to", "Enter at least one address to send alerts to.")
        if not e["smtp_host"]:
            raise validation.ValidationError("email.smtp_host", "Enter the SMTP server, e.g. smtp.isp.example.")
        if not e["from"]:
            raise validation.ValidationError("email.from", "Enter the sender address, e.g. dnsone@isp.example.")
        if not 1 <= e["smtp_port"] <= 65535:
            raise validation.ValidationError("email.smtp_port", "Enter a port between 1 and 65535.")

    hook = data.get("webhook") or {}
    cfg["webhook"]["enabled"] = bool(hook.get("enabled"))
    cfg["webhook"]["url"] = _url(str(hook.get("url") or ""), "webhook.url") if hook.get("enabled") or hook.get("url") else ""

    tg = data.get("telegram") or {}
    t = cfg["telegram"]
    t["enabled"] = bool(tg.get("enabled"))
    t["bot_token"] = str(tg.get("bot_token") or "").strip() or old["telegram"]["bot_token"]
    t["chat_id"] = str(tg.get("chat_id") or "").strip()[:64]
    if t["enabled"] and not (t["bot_token"] and t["chat_id"]):
        raise validation.ValidationError("telegram.chat_id", "Enter the bot token (from @BotFather) and the chat id.")

    row = db.get(Setting, CONFIG_KEY)
    if row is None:
        db.add(Setting(name=CONFIG_KEY, value=cfg))
    else:
        row.value = cfg
    return public_config_from(cfg)


# --------------------------------------------------------------------------- what is wrong


def _dynamic_blocks(s: Settings) -> dict | None:
    if not s.dnsdist_api_key:
        return None
    try:
        response = httpx.get(f"{s.dnsdist_api_url}/jsonstat", params={"command": "dynblocklist"}, headers={"X-API-Key": s.dnsdist_api_key}, timeout=3)
        response.raise_for_status()
        return response.json() or {}
    except (httpx.HTTPError, ValueError):
        return None


def current_problems(db: Session, settings: Settings | None = None) -> list[dict]:
    """Everything wrong right now on this node: {"key", "severity", "title", "detail"}."""
    s = settings or get_settings()
    primary = s.role == "primary"
    out = []
    for check in health.checks(db, s):
        if check["status"] == "ok" or (check["name"] in SHARED_CHECKS and not primary):
            continue
        out.append({"key": f"health:{check['name']}", "severity": check["status"], "title": check["name"], "detail": check["detail"]})
    if primary:
        for bl in db.scalars(select(Blocklist).where(Blocklist.enabled.is_(True), Blocklist.last_status == "error")):
            out.append({"key": f"blocklist:{bl.id}", "severity": "warning", "title": f"Blocklist {bl.name}",
                        "detail": f"download failed: {(bl.last_error or 'unknown error')[:300]}"})
    blocks = _dynamic_blocks(s)
    if blocks:
        top = sorted(blocks.items(), key=lambda kv: -int((kv[1] or {}).get("blocks", 0)))[:10]
        listed = ", ".join(f"{net} ({(info or {}).get('reason', 'flood')})" for net, info in top)
        out.append({"key": "flood", "severity": "warning", "title": "Query flood",
                    "detail": f"dnsdist is refusing {len(blocks)} address(es) for 60 s at a time: {listed}"})
    return out


# --------------------------------------------------------------------------- delivery


def _text(node: str, firing: list[dict], resolved: list[dict]) -> tuple[str, str]:
    parts = []
    if firing:
        parts.append(f"{len(firing)} problem(s)")
    if resolved:
        parts.append(f"{len(resolved)} resolved")
    subject = f"[DNSOne {node}] " + ", ".join(parts)
    lines = []
    for a in firing:
        mark = "ERROR" if a["severity"] == "error" else "WARNING"
        lines.append(f"{mark} {a['title']}: {a['detail']} (since {a['since']} UTC)")
    for a in resolved:
        lines.append(f"RESOLVED {a['title']} (was: {a['detail']})")
    return subject, "\n".join(lines)


def _send_email(cfg: dict, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, cfg["from"], ", ".join(cfg["to"])
    msg.set_content(body + "\n\n-- \nDNSOne alerts (Settings → Alerts)\n")
    context = ssl.create_default_context()
    if cfg["smtp_security"] == "tls":
        server = smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], timeout=TIMEOUT, context=context)
    else:
        server = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=TIMEOUT)
    with server:
        if cfg["smtp_security"] == "starttls":
            server.starttls(context=context)
        if cfg["smtp_user"]:
            server.login(cfg["smtp_user"], cfg["smtp_password"])
        server.send_message(msg)


def _send_webhook(cfg: dict, payload: dict) -> None:
    httpx.post(cfg["url"], json=payload, timeout=TIMEOUT).raise_for_status()


def _send_telegram(cfg: dict, text: str) -> None:
    url = f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage"
    httpx.post(url, json={"chat_id": cfg["chat_id"], "text": text[:4000], "disable_web_page_preview": True}, timeout=TIMEOUT).raise_for_status()


def deliver(cfg: dict, node: str, firing: list[dict], resolved: list[dict]) -> dict[str, str]:
    """Sends one message per channel. Returns {channel: "ok" | error text}."""
    subject, body = _text(node, firing, resolved)
    payload = {"text": f"{subject}\n{body}", "node": node,
               "alerts": [{**a, "state": "firing"} for a in firing] + [{**a, "state": "resolved"} for a in resolved]}
    results: dict[str, str] = {}
    channels = (("email", lambda: _send_email(cfg["email"], subject, body)),
                ("webhook", lambda: _send_webhook(cfg["webhook"], payload)),
                ("telegram", lambda: _send_telegram(cfg["telegram"], f"{subject}\n{body}")))
    for name, send in channels:
        if not cfg[name]["enabled"]:
            continue
        try:
            send()
            results[name] = "ok"
        except (OSError, smtplib.SMTPException, httpx.HTTPError) as exc:
            # Never the URL or token in the message: Telegram's URL carries the bot token.
            reason = f"HTTP {exc.response.status_code}" if isinstance(exc, httpx.HTTPStatusError) else exc.__class__.__name__
            results[name] = f"failed: {reason}" + (f" ({exc})" if isinstance(exc, (smtplib.SMTPException, ConnectionRefusedError)) else "")
            log.warning("alert delivery via %s failed: %s", name, results[name])
    return results


def send_test(db: Session, settings: Settings | None = None) -> dict[str, str]:
    s = settings or get_settings()
    cfg = get_config(db)
    sample = {"key": "test", "severity": "warning", "title": "Test alert", "since": utcnow().isoformat(timespec="minutes"),
              "detail": "Sent from Settings → Alerts. If you read this, alerts reach you."}
    results = deliver(cfg, s.node_name, [sample], [])
    if not results:
        return {"none": "no channel is turned on"}
    return results


# --------------------------------------------------------------------------- the check


def check(db: Session, settings: Settings | None = None, now: datetime | None = None) -> dict:
    """One run: compare what is wrong with the stored state, notify the changes, store the state."""
    s = settings or get_settings()
    now = now or utcnow()
    cfg = get_config(db)
    row = db.get(Setting, _state_key(s.node_name))
    state = dict(row.value) if row else {}
    active: dict = dict(state.get("active") or {})

    problems = {p["key"]: p for p in current_problems(db, s) if cfg["warnings"] or p["severity"] == "error"}
    firing, resolved = [], []
    for key, p in problems.items():
        a = active.get(key) or {"since": now.isoformat(timespec="seconds"), "notified_at": None}
        a.update({"severity": p["severity"], "title": p["title"], "detail": p["detail"], "key": key})
        active[key] = a
        since = datetime.fromisoformat(a["since"])
        due = now - since >= timedelta(minutes=cfg["for_minutes"]) - timedelta(seconds=5)
        last = datetime.fromisoformat(a["notified_at"]) if a.get("notified_at") else None
        repeat = last is not None and cfg["repeat_hours"] and now - last >= timedelta(hours=cfg["repeat_hours"])
        if due and (last is None or repeat):
            firing.append(a)
    for key in [k for k in active if k not in problems]:
        a = active.pop(key)
        if a.get("notified_at"):
            resolved.append(a)

    delivery = state.get("last_delivery")
    if cfg["enabled"] and (firing or resolved):
        results = deliver(cfg, s.node_name, firing, resolved)
        delivery = {"at": now.isoformat(timespec="seconds"), "results": results}
        if results and any(v == "ok" for v in results.values()):
            for a in firing:
                a["notified_at"] = now.isoformat(timespec="seconds")
    value = {"node": s.node_name, "checked_at": now.isoformat(timespec="seconds"), "active": active, "last_delivery": delivery}
    if row is None:
        db.add(Setting(name=_state_key(s.node_name), value=value))
    else:
        row.value = value
    db.commit()
    return {"active": list(active.values()), "sent": [a["key"] for a in firing], "resolved": [a["key"] for a in resolved], "delivery": delivery}


def overview(db: Session) -> list[dict]:
    """Active alerts of every node (Dashboard, Settings → Alerts)."""
    out = []
    for row in db.scalars(select(Setting).where(Setting.name.like("alerts.state.%")).order_by(Setting.name)):
        v = row.value or {}
        for a in (v.get("active") or {}).values():
            out.append({**a, "node": v.get("node")})
    return sorted(out, key=lambda a: (a["severity"] != "error", a["since"]))


def states(db: Session) -> list[dict]:
    return [{"node": (r.value or {}).get("node"), "checked_at": (r.value or {}).get("checked_at"), "last_delivery": (r.value or {}).get("last_delivery")}
            for r in db.scalars(select(Setting).where(Setting.name.like("alerts.state.%")).order_by(Setting.name))]
