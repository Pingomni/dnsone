"""The time zone the console shows times in (Settings → Overview → Time zone).

Stored in MySQL (settings 'console.timezone'), so every API worker and every node of a cluster
shows the same one. Until an operator chooses one it is DNSONE_TIMEZONE, which install.sh sets
to the server's own zone. Timestamps stay UTC in the database; only what the console shows changes.
"""

from __future__ import annotations

import logging
import time
from datetime import timezone, tzinfo
from functools import lru_cache
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from sqlalchemy.orm import Session

from . import validation
from .config import get_settings
from .models import Setting

log = logging.getLogger(__name__)

KEY = "console.timezone"
# How long a process trusts what it last read: the other API workers follow a change within this.
TTL = 2.0
_cached: tuple[float, str] | None = None


@lru_cache(maxsize=1)
def choices() -> tuple[str, ...]:
    """Every IANA zone this server knows, UTC first."""
    names = available_timezones()
    return ("UTC", *sorted(n for n in names if n != "UTC" and not n.startswith(("SystemV/", "localtime", "Factory"))))


def _valid(name: object) -> bool:
    return isinstance(name, str) and name in choices()


def default() -> str:
    """DNSONE_TIMEZONE, or UTC if that is not a zone."""
    name = get_settings().timezone
    return name if _valid(name) else "UTC"


def _read(db: Session) -> str:
    global _cached
    row = db.get(Setting, KEY)
    value = row.value.get("name") if row is not None and isinstance(row.value, dict) else None
    name = value if _valid(value) else default()
    _cached = (time.monotonic(), name)
    return name


def name(db: Session | None = None) -> str:
    """The zone's IANA name. With a session it is read now; without one, at most TTL seconds ago."""
    if db is not None:
        return _read(db)
    if _cached is not None and time.monotonic() - _cached[0] < TTL:
        return _cached[1]
    from .db import new_session
    session = new_session()
    try:
        return _read(session)
    except Exception:  # noqa: BLE001 - showing times must not fail with the database
        log.warning("could not read the console time zone; using the last known one", exc_info=True)
        return _cached[1] if _cached is not None else default()
    finally:
        session.close()


def zone() -> tzinfo:
    try:
        return ZoneInfo(name())
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


def store(db: Session, value: str) -> str:
    global _cached
    value = str(value or "").strip()
    if not _valid(value):
        raise validation.ValidationError("timezone", "Choose a time zone from the list, e.g. Europe/Tirane or UTC.")
    row = db.get(Setting, KEY)
    if row is None:
        db.add(Setting(name=KEY, value={"name": value}))
    else:
        row.value = {"name": value}
    _cached = (time.monotonic(), value)
    return value
