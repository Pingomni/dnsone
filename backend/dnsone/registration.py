"""Registering a DNSOne server: every server, DNSOne Community included, has a licence key from its PingOmni account.

The free key is a DNSOne Community licence from account.pingomni.com (price 0, valid a year, renewed for free): a
key like a Pro key, signed the same way (license.py), whose edition is "community" and whose features are [], so it
turns no Pro feature on. A Pro key registers the server as well.

Only the web console asks for a key. DNS, PowerDNS, the query log, cluster sync, the jobs, the health checks and the
machine-to-machine endpoints never look here: a missing licence never changes a DNS answer.

States (status()):
  registered  a key that verifies and is valid, or that expired less than RENEW_DAYS ago.
  grace       not registered, for GRACE_DAYS from the first time this check found the server so (new installs and
              servers that ran before keys were needed alike). The day is stored in the Setting GRACE_KEY and never
              cleared, so the grace does not start again: a key removed after it ended locks the console at once.
              The console shows a banner with the days left.
  locked      not registered after the grace: the console's API refuses every route but EXEMPT (403, code
              registration_required), and the console shows the "Register this server" screen. Storing a key
              (Settings → License, which stays open) unlocks it at once, without a restart.
"""
from __future__ import annotations

import logging
from datetime import date, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import license
from .models import Setting

log = logging.getLogger(__name__)

GRACE_KEY = "registration_grace_started"
GRACE_DAYS = 30
RENEW_DAYS = 30
CODE = "registration_required"
URL = "https://account.pingomni.com/buy?product=dnsone&plan=Community&period=12"

# What the console's API still answers while it is locked: signing in and out, the session, two-step and single
# sign-on, the licence (read it with the server ID, store or remove a key; registration with the account portal
# runs in the background, activation.py), the health checks, and what machines call without the console: dynamic
# DNS updates from routers, the legal notice page, Prometheus, and joining or leaving a cluster (a server that joins
# takes the cluster's licence). Calls with an app password (scripts) are not the console and are never refused.
# Everything outside /api/ (the console's files) is served as before.
EXEMPT = frozenset({
    "/api/auth/login", "/api/auth/login/verify", "/api/auth/logout", "/api/auth/me",
    "/api/auth/oidc", "/api/auth/oidc/login", "/api/auth/oidc/callback",
    "/api/settings/license",
    "/api/health", "/api/system/health",
    "/api/ddns/nic/update", "/api/legal/notice", "/api/metrics",
    "/api/cluster/join", "/api/cluster/leave",
})

# The grace's first day, once stored: it never changes, so each process reads it once.
_grace: date | None = None


def registered(lic: dict, today: date | None = None) -> bool:
    """Does this licence (license.get / current) register the server?"""
    if lic.get("state") == "valid":
        return True
    if lic.get("state") == "expired":
        today = today or date.today()
        return (today - date.fromisoformat(lic["expires"])).days < RENEW_DAYS
    return False


def status(lic: dict, started: date | None, today: date | None = None) -> dict:
    """The registration state for a licence and the grace's first day (None while registered), for the console."""
    today = today or date.today()
    edition = lic.get("edition")
    if registered(lic, today):
        return {"state": "registered", "edition": edition, "url": URL}
    # Why not: no key, a key that does not verify (or is for another server), or a key that expired too long ago.
    reason = "expired" if lic.get("state") == "expired" else "invalid" if lic.get("error") else "none"
    started = started or today
    ends = started + timedelta(days=GRACE_DAYS)
    days_left = max((ends - today).days, 0)
    return {"state": "grace" if days_left > 0 else "locked", "reason": reason, "edition": edition, "days_left": days_left,
            "grace_started": started.isoformat(), "grace_ends": ends.isoformat(), "url": URL}


def grace_started(db: Session, today: date | None = None) -> date:
    """The day this server was first found without a registration: stored the first time it is asked for, then kept.
    The caller commits."""
    row = db.get(Setting, GRACE_KEY)
    try:
        if row is not None:
            return date.fromisoformat(row.value["date"])
    except (KeyError, TypeError, ValueError):
        log.warning("%s is damaged: the grace starts today", GRACE_KEY)
    today = today or date.today()
    if row is None:
        db.add(Setting(name=GRACE_KEY, value={"date": today.isoformat()}))
    else:
        row.value = {"date": today.isoformat()}
    return today


def check(db: Session, today: date | None = None) -> dict:
    """The registration state from the database (the grace's first day stored if it starts now). The caller commits."""
    lic = license.get(db)
    if registered(lic, today):
        return status(lic, None, today)
    return status(lic, grace_started(db, today), today)


def _stored_grace() -> date:
    global _grace
    if _grace is not None:
        return _grace
    from .db import new_session
    try:
        db = new_session()
        try:
            try:
                started = grace_started(db)
                db.commit()
            except IntegrityError:  # another process stored it first: use theirs
                db.rollback()
                started = grace_started(db)
        finally:
            db.close()
    except Exception as exc:  # noqa: BLE001: the database is down; the console stays open (grace), asked again later
        log.warning("registration grace not read: %s", exc)
        return date.today()
    _grace = started
    return started


def current() -> dict:
    """This server's registration state, from the cached licence (license.current: storing a key shows at once)."""
    lic = license.current()
    if registered(lic):
        return status(lic, None)
    return status(lic, _stored_grace())


def refused(method: str, path: str, headers) -> bool:
    """Is this request one the console's API refuses while the server is locked (a console route, not EXEMPT)?"""
    if not path.startswith("/api/") or method == "OPTIONS":
        return False
    if path.rstrip("/") in EXEMPT:
        return False
    # App passwords: scripts and monitoring, not the web console.
    return headers.get("authorization", "")[:7].lower() != "bearer "


def error(state: dict) -> dict:
    """The body of the 403 a locked console's API answers."""
    if state.get("reason") == "expired":
        message = "Renew your free licence at account.pingomni.com: this server's licence expired more than 30 days ago."
    else:
        message = "Register this server: get a free DNSOne licence at account.pingomni.com and add it under Settings → License."
    return {"message": message, "errors": {}, "code": CODE, "registration": state}
