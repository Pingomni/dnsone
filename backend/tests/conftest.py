"""Fixtures for the end-to-end tests (see test_integration.py for the test stack they need)."""

from __future__ import annotations

import os

import pytest

from helpers import PASSWORD, _load_env


@pytest.fixture(scope="module")
def client():
    _load_env()
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text

    from dnsone import migrate, security
    from dnsone.config import get_settings
    from dnsone.db import get_engine, session_scope
    from dnsone.models import Role, User

    get_settings.cache_clear()
    get_engine.cache_clear()
    url = os.environ["DNSONE_DATABASE_URL"]
    server, _, rest = url.rpartition("/")
    name = rest.split("?")[0]
    with create_engine(server + "/").begin() as conn:
        conn.execute(text(f"DROP DATABASE IF EXISTS `{name}`"))
        conn.execute(text(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"))
    migrate.run(get_engine(), log=lambda _m: None)
    with session_scope() as db:
        admin = db.query(Role).filter_by(name="admin").one()
        viewer = db.query(Role).filter_by(name="viewer").one()
        db.add(User(username="admin", name="Admin", role_id=admin.id, password_hash=security.hash_password(PASSWORD)))
        db.add(User(username="viewer", name="Viewer", role_id=viewer.id, password_hash=security.hash_password(PASSWORD)))

    from dnsone.api import create_app

    with TestClient(create_app()) as c:
        response = c.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
        assert response.status_code == 200, response.text
        c.headers["X-CSRF-Token"] = response.json()["csrf"]
        yield c
    # Leave the BIND, Recursor and dnsdist test instances clean for the next run.
    from dnsone import rpz, runtime
    from dnsone.zonegen import Publisher
    with session_scope() as db:
        db.execute(text("DELETE FROM zones"))
        db.execute(text("DELETE FROM rpz_rules"))
        db.execute(text("DELETE FROM blocklists"))
        db.execute(text("DELETE FROM client_groups WHERE built_in = 0"))
        db.execute(text("UPDATE client_groups SET blocking = 1"))
        db.execute(text("DELETE FROM settings WHERE name IN ('cluster.secondaries', 'rpz.pause', 'dns.server', 'querylog.privacy')"))
        db.execute(text("""UPDATE settings SET value = JSON_OBJECT('action', 'nxdomain', 'walled_garden_target', '', 'block_subdomains', TRUE) WHERE name = 'rpz.policy'"""))
        rpz.mark_changed(db)
    Publisher().reconcile()
    rpz.RpzBuilder().build()
    runtime.apply()


