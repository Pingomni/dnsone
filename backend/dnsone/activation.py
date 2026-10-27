"""Registering this server's licence with the PingOmni account portal (report only).

Once a Pro key is installed, the primary node tells the portal which server it runs on: it activates
(`POST /api/v1/activate` with the key, a fingerprint and the host name), then checks in every
CHECK_IN_HOURS (`POST /api/v1/check-in`). The customer then sees the server, and its last check-in, on
the licence's page in their PingOmni account. dnsone-stats.timer calls run() every minute; run() only
talks to the portal when something is due, and never raises.

Report only: nothing here turns a Pro feature on or off. A portal that cannot be reached, or refuses
(the licence already runs on another server), is shown under Settings → License and retried later;
license.py alone decides what the key allows. One thing the portal sends back is used: after a renewal
the check-in carries the renewed key, and it replaces the stored one (license.parse verifies it first).

The fingerprint is the sha256 of /etc/machine-id: stable across reboots and upgrades, readable by the
dnsone user, and only its hash leaves the server. DNSONE_ACCOUNT_URL="" turns registration off.
"""
from __future__ import annotations

import hashlib
import logging
import socket
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy.orm import Session

from . import license
from .config import get_settings
from .models import Setting

log = logging.getLogger(__name__)

KEY = "license_activation"
CHECK_IN_HOURS = 12
# After a failure: the portal could not be reached (retry soon), or it refused (retry twice a day).
RETRY_UNREACHABLE = timedelta(hours=1)
RETRY_REFUSED = timedelta(hours=CHECK_IN_HOURS)
TIMEOUT = 8.0


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def fingerprint() -> str:
    """This server's id for the portal: sha256 of its machine id (the host name when there is none)."""
    try:
        machine = get_settings().machine_id_file.read_text().strip()
    except OSError:
        machine = ""
    return hashlib.sha256(f"dnsone:{machine or socket.gethostname()}".encode()).hexdigest()


def _load(db: Session) -> dict:
    row = db.get(Setting, KEY)
    return dict(row.value or {}) if row else {}


def _save(db: Session, state: dict) -> None:
    row = db.get(Setting, KEY)
    if row is None:
        db.add(Setting(name=KEY, value=state))
    else:
        row.value = state


def _stored_key(db: Session) -> str | None:
    row = db.get(Setting, license.KEY)
    return (row.value or {}).get("key") if row else None


def _due(state: dict, licence_id: str, now: datetime) -> bool:
    if state.get("license_id") != licence_id or not state.get("last_attempt"):
        return True  # a new key: register it now
    last = datetime.fromisoformat(state["last_attempt"])
    wait = {"registered": timedelta(hours=CHECK_IN_HOURS), "unreachable": RETRY_UNREACHABLE}.get(state.get("status", ""), RETRY_REFUSED)
    return now - last >= wait


def _message(response: httpx.Response) -> tuple[str, str]:
    try:
        body = response.json()
    except ValueError:
        body = {}
    return str(body.get("error") or f"http_{response.status_code}"), str(body.get("message") or f"The account portal answered HTTP {response.status_code}.")


def run(db: Session, force: bool = False, client: httpx.Client | None = None) -> dict:
    """Activate or check in when due; returns the stored state. The caller commits."""
    s = get_settings()
    if not s.account_url or s.role == "replica":
        return _load(db)
    state = _load(db)
    key = _stored_key(db)
    now = _now()
    own = client is None
    client = client or httpx.Client(base_url=s.account_url, timeout=TIMEOUT, headers={"User-Agent": "DNSOne"})
    try:
        if not key:
            # The licence was removed: give the server up in the portal, then forget it.
            if state.get("token"):
                try:
                    client.post("/api/v1/deactivate", json={"token": state["token"], "fingerprint": state.get("fingerprint", fingerprint())})
                except httpx.HTTPError as exc:
                    log.info("licence deactivation not sent: %s", exc)
                db.query(Setting).filter(Setting.name == KEY).delete()
            return {}
        try:
            payload = license.parse(key)
        except license.LicenseError:
            return state
        if not force and not _due(state, payload["id"], now):
            return state

        fp = fingerprint()
        base = {"license_id": payload["id"], "fingerprint": fp, "hostname": s.node_name, "last_attempt": now.isoformat()}
        try:
            response = None
            if state.get("token") and state.get("license_id") == payload["id"] and state.get("fingerprint") == fp:
                response = client.post("/api/v1/check-in", json={"token": state["token"], "fingerprint": fp})
                if response.status_code in (404, 409, 410):
                    response = None  # this registration is gone (released, or another server): register again
            if response is None:
                response = client.post("/api/v1/activate", json={"key": key, "fingerprint": fp, "hostname": s.node_name})
        except httpx.HTTPError as exc:
            state = {**state, **base, "status": "unreachable", "message": f"{s.account_url} could not be reached: {exc.__class__.__name__}."}
            _save(db, state)
            return state

        if response.status_code == 200:
            data = response.json()
            state = {**base, "status": "registered", "message": "", "token": data.get("token") or state.get("token"),
                     "last_ok": now.isoformat(), "lease_until": data.get("lease_until")}
            renewed = data.get("key")
            if renewed and "".join(renewed.split()) != key:
                try:
                    if license.parse(renewed)["id"] == payload["id"]:
                        license.store(db, renewed)
                        state["message"] = "The renewed licence key from your PingOmni account was installed."
                        state["license_id"] = payload["id"]
                except license.LicenseError as exc:
                    log.warning("renewed licence key from the portal ignored: %s", exc)
        elif response.status_code >= 500:
            state = {**state, **base, "status": "unreachable", "message": f"The account portal answered HTTP {response.status_code}."}
        else:
            code, message = _message(response)
            state = {**base, "status": "in_use" if code == "in_use" else "refused", "code": code, "message": message}
        _save(db, state)
        return state
    finally:
        if own:
            client.close()


def run_safely() -> None:
    """For dnsone-stats.timer: run() in its own session; a failure is logged, never raised."""
    from .db import session_scope
    try:
        with session_scope() as db:
            run(db)
    except Exception as exc:  # noqa: BLE001: registration must never stop the statistics job
        log.warning("licence registration skipped: %s", exc)


def public(db: Session) -> dict:
    """What Settings → License shows."""
    s = get_settings()
    state = _load(db)
    if not s.account_url:
        status = "off"
    elif s.role == "replica":
        status = "replica"
    else:
        status = state.get("status", "pending")
    return {"status": status, "message": state.get("message", ""), "account_url": s.account_url, "hostname": state.get("hostname"),
            "last_ok": state.get("last_ok"), "last_attempt": state.get("last_attempt")}
