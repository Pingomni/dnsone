# SPDX-License-Identifier: Elastic-2.0
# DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
"""Quotas of accounts limited to their own zones (customers, resellers): how many zones they may hold,
how many records a zone may have when they change it, and how many API requests they may make a minute.

Administrators set them for anyone (Settings → Users), resellers for their own customers (Customers),
never above their own. Accounts that see every zone (operators, administrators) have none. A limit is
checked when the account itself acts: an administrator adding records to a customer's zone is not held
back by the customer's quota.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .db import get_engine
from .models import Record, User, user_zones
from .system import utcnow

FIELDS = ("max_zones", "max_records", "api_rate")
LIMITS = {"max_zones": 100_000, "max_records": 1_000_000, "api_rate": 100_000}


class QuotaExceeded(Exception):
    def __init__(self, field: str, message: str):
        super().__init__(message)
        self.field = field
        self.message = message


def applies(user: User) -> bool:
    return user.role.zone_scope == "assigned"


def zone_count(db: Session, user_id: int) -> int:
    return db.scalar(select(func.count()).select_from(user_zones).where(user_zones.c.user_id == user_id)) or 0


def check_zones(db: Session, user: User, adding: int = 1) -> None:
    """Before an account creates (or is given) `adding` more zones."""
    if not applies(user) or user.max_zones is None or adding <= 0:
        return
    held = zone_count(db, user.id)
    if held + adding > user.max_zones:
        raise QuotaExceeded("max_zones", f"{user.username} may hold at most {user.max_zones} zone(s) and holds {held}.")


def check_records(db: Session, user: User, zone_id: int, adding: int) -> None:
    """Before an account adds `adding` records (net) to a zone."""
    if not applies(user) or user.max_records is None or adding <= 0:
        return
    have = db.scalar(select(func.count()).select_from(Record).where(Record.zone_id == zone_id)) or 0
    if have + adding > user.max_records:
        raise QuotaExceeded("max_records", f"Your account allows at most {user.max_records} records per zone; this zone has {have}"
                                           f" and the change adds {adding}.")


def check_rate(user: User) -> int | None:
    """Counts one API request of the account; returns the seconds to wait if it is over its rate.

    The counter has its own connection: a GET request's session is never committed.
    """
    if user.api_rate is None or not applies(user):
        return None
    now = utcnow()
    minute = now.replace(second=0, microsecond=0)
    with get_engine().begin() as conn:
        conn.execute(text("INSERT INTO api_usage (user_id, minute, requests) VALUES (:u, :m, 1) "
                          "ON DUPLICATE KEY UPDATE requests = requests + 1"), {"u": user.id, "m": minute})
        used = conn.scalar(text("SELECT requests FROM api_usage WHERE user_id = :u AND minute = :m"), {"u": user.id, "m": minute}) or 0
    if used > user.api_rate:
        return max(1, 60 - now.second)
    return None


def usage(db: Session, user: User) -> dict:
    minute = utcnow().replace(second=0, microsecond=0)
    used = db.execute(text("SELECT requests FROM api_usage WHERE user_id = :u AND minute = :m"), {"u": user.id, "m": minute}).scalar() or 0
    return {"zones": zone_count(db, user.id), "requests_this_minute": int(used)}


def cleanup(db: Session) -> None:
    db.execute(text("DELETE FROM api_usage WHERE minute < :t"), {"t": utcnow() - timedelta(minutes=10)})


def clean(values: dict, cap: User | None) -> dict:
    """Quota fields from a form: None (no limit) or a whole number; a reseller's customers stay within its own."""
    out = {}
    for field in FIELDS:
        if field not in values:
            continue
        value = values[field]
        if value is not None:
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise QuotaExceeded(field, "Enter a whole number, or leave it empty for no limit.") from None
            if not 0 <= value <= LIMITS[field]:
                raise QuotaExceeded(field, f"Enter a number between 0 and {LIMITS[field]:,}, or leave it empty for no limit.")
        own = getattr(cap, field) if cap is not None else None
        if own is not None and (value is None or value > own):
            raise QuotaExceeded(field, f"At most {own}: your own limit.")
        out[field] = value
    return out
