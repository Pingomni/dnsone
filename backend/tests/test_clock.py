"""The console's time zone (Settings → Overview → Time zone): clock.py against an in-memory database."""

from datetime import datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from dnsone import clock, security, validation
from dnsone.models import Setting


@pytest.fixture
def db(monkeypatch):
    engine = create_engine("sqlite://")
    with engine.begin() as conn:  # MySQL fills updated_at itself (migrations/0001_initial.sql)
        conn.execute(text("CREATE TABLE settings (name VARCHAR(64) PRIMARY KEY, value JSON, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)"))
    monkeypatch.setenv("DNSONE_DATABASE_URL", "sqlite://")
    monkeypatch.setenv("DNSONE_TIMEZONE", "Europe/Tirane")
    from dnsone.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setattr(clock, "_cached", None)
    with Session(engine) as session:
        yield session
    get_settings.cache_clear()


def test_default_is_the_env_zone(db):
    assert clock.default() == "Europe/Tirane"
    assert clock.name(db) == "Europe/Tirane"


def test_store_and_read(db):
    assert clock.store(db, " America/New_York ") == "America/New_York"
    db.flush()
    assert clock.name(db) == "America/New_York"
    # Without a session the last value read is used (for TTL seconds): what security.iso() formats with.
    assert clock.name() == "America/New_York"
    assert security.iso(datetime(2026, 1, 15, 12, 0, 0)) == "2026-01-15 07:00:00"
    assert security.iso(datetime(2026, 7, 15, 12, 0, 0)) == "2026-07-15 08:00:00"  # daylight saving time
    clock.store(db, "UTC")
    assert security.iso(datetime(2026, 7, 15, 12, 0, 0)) == "2026-07-15 12:00:00"


@pytest.mark.parametrize("bad", ["", "Mars/Olympus", "../../etc/passwd", "europe/tirane x"])
def test_unknown_zones_are_refused(db, bad):
    with pytest.raises(validation.ValidationError) as exc:
        clock.store(db, bad)
    assert exc.value.field == "timezone"
    assert db.get(Setting, clock.KEY) is None


def test_a_stored_zone_that_no_longer_exists_falls_back(db):
    db.add(Setting(name=clock.KEY, value={"name": "Nowhere/Gone"}))
    db.flush()
    assert clock.name(db) == "Europe/Tirane"


def test_choices():
    choices = clock.choices()
    assert choices[0] == "UTC" and "Europe/Tirane" in choices and len(choices) == len(set(choices))
