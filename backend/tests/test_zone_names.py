"""Offline: a reseller or customer cannot create a zone inside, or above, another account's zone."""
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from dnsone import validation
from dnsone.api.zones import _new_zone_name


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    with Session(engine) as session:
        # The check reads only zones.id and zones.name.
        session.execute(text("CREATE TABLE zones (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)"))
        session.execute(text("INSERT INTO zones VALUES (1, 'victim.example'), (2, 'mine.example')"))
        yield session


def actor(zones, all_zones=False):
    return SimpleNamespace(all_zones=all_zones, zone_ids=lambda db: set(zones))


@pytest.mark.parametrize("name", ["sub.victim.example", "a.b.victim.example", "example"])
def test_inside_or_above_someone_elses_zone_is_refused(db, name):
    with pytest.raises(validation.ValidationError):
        _new_zone_name(db, actor({2}), name)


@pytest.mark.parametrize("name", ["sub.mine.example", "other.example", "victimexample.org", "xvictim.example"])
def test_own_or_unrelated_names_pass(db, name):
    _new_zone_name(db, actor({2}), name)


def test_administrators_and_reserved_names(db):
    _new_zone_name(db, actor(set(), all_zones=True), "sub.victim.example")
    with pytest.raises(validation.ValidationError):
        _new_zone_name(db, actor(set(), all_zones=True), "catalog.dnsone")
