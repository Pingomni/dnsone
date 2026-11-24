"""Registering a server with a licence key, the free DNSOne Community one included (registration.py, license.py): the
grace, the locked console and what stays open. A settings store in memory and the API in process; no services needed."""
from __future__ import annotations

import ast
import base64
import json
from datetime import date, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dnsone import edition, license, registration
from dnsone.models import Setting

TODAY = date.today()
COMMUNITY = {"product": "dnsone", "servers": 1, "edition": "community"}


@pytest.fixture()
def signer(monkeypatch):
    """A signing key the licence module trusts for this test only; issue() signs a payload as the portal does."""
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    monkeypatch.setattr(license, "PUBLIC_KEYS", [public])

    def issue(expires: date, features=(), lid="c1", **extra) -> str:
        payload = json.dumps({"v": 1, "id": lid, "customer": "Test ISP", "issued": "2026-01-01", "expires": expires.isoformat(),
                              "features": list(features), **extra}).encode()
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
        return f"DNSONE1.{b64(payload)}.{b64(key.sign(payload))}"

    return issue


class FakeDb:
    """The settings rows license.py and registration.py read and write, as one shared database."""

    def __init__(self):
        self.rows: dict[str, Setting] = {}

    def get(self, _model, name):
        return self.rows.get(name)

    def add(self, row):
        self.rows[row.name] = row

    def delete(self, row):
        self.rows.pop(row.name, None)

    def scalars(self, _stmt):
        return []

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


@pytest.fixture()
def db(monkeypatch):
    """Every session (license.current, the grace, the API's get_db) is this one store; caches start empty."""
    store = FakeDb()
    monkeypatch.setattr("dnsone.db.new_session", lambda: store)
    monkeypatch.setattr(registration, "_grace", None)
    license.invalidate()
    yield store
    license.invalidate()


def grace_from(db: FakeDb, day: date) -> None:
    db.add(Setting(name=registration.GRACE_KEY, value={"date": day.isoformat()}))


def test_a_community_key_is_accepted_and_turns_no_pro_feature_on(signer, monkeypatch):
    lic = license.describe(license.parse(signer(TODAY + timedelta(days=365), **COMMUNITY)))
    assert lic["state"] == "valid" and lic["edition"] == "community" and lic["features"] == [] and lic["servers"] == 1
    # Even a community key that listed features would not turn them on.
    assert license.parse(signer(TODAY, features=("all",), **COMMUNITY))["features"] == []
    monkeypatch.setattr(license, "current", lambda: lic)
    assert edition.name() == "community" and edition.features() == []
    assert not any(license.allows(f) for f in license.FEATURES) and not edition.pro("legal")
    assert registration.registered(lic)
    # Pro keys name their edition, or (older ones) do not: they are Pro.
    assert license.parse(signer(TODAY, features=("all",), edition="pro"))["edition"] == "pro"
    assert license.parse(signer(TODAY, features=("all",)))["edition"] == "pro"
    with pytest.raises(license.LicenseError):
        license.parse(signer(TODAY, edition="enterprise"))


def test_registered_until_thirty_days_after_expiry(signer):
    def lic(days_ago: int) -> dict:
        return license.describe(license.parse(signer(TODAY - timedelta(days=days_ago), **COMMUNITY)))

    assert registration.registered(lic(0)) and registration.registered(lic(29))
    assert not registration.registered(lic(31)) and not registration.registered(license.describe(None))


def test_the_grace_starts_once_and_never_again(signer, db):
    # First found without a key: the grace starts today, and the console works with a banner.
    state = registration.check(db, TODAY)
    assert state["state"] == "grace" and state["days_left"] == 30 and state["reason"] == "none"
    assert db.rows[registration.GRACE_KEY].value == {"date": TODAY.isoformat()}
    assert registration.check(db, TODAY + timedelta(days=29))["days_left"] == 1
    assert registration.check(db, TODAY + timedelta(days=30))["state"] == "locked"

    # A key registers the server; the grace's day stays stored, ignored.
    license.store(db, signer(TODAY + timedelta(days=365), **COMMUNITY))
    assert registration.check(db, TODAY + timedelta(days=40))["state"] == "registered"
    assert db.rows[registration.GRACE_KEY].value == {"date": TODAY.isoformat()}
    # Removed after the grace ended: locked at once, the grace does not start again.
    license.remove(db)
    assert registration.check(db, TODAY + timedelta(days=40))["state"] == "locked"

    # A key that does not verify counts as none.
    db.rows[license.KEY] = Setting(name=license.KEY, value={"key": "DNSONE1.e30.AAAA"})
    assert registration.check(db, TODAY + timedelta(days=40))["reason"] == "invalid"


def test_a_server_registered_from_the_start_stores_no_grace(signer, db):
    license.store(db, signer(TODAY + timedelta(days=365), **COMMUNITY))
    assert registration.check(db)["state"] == "registered" and registration.GRACE_KEY not in db.rows


def test_an_expired_key_past_thirty_days_locks(signer, db):
    grace_from(db, TODAY - timedelta(days=400))
    license.store(db, signer(TODAY - timedelta(days=31), **COMMUNITY))
    state = registration.check(db)
    assert state["state"] == "locked" and state["reason"] == "expired"
    assert "Renew your free licence at account.pingomni.com" in registration.error(state)["message"]
    # Expired less than 30 days ago: still registered.
    license.store(db, signer(TODAY - timedelta(days=10), **COMMUNITY))
    assert registration.check(db)["state"] == "registered"


def test_exempt_routes():
    for path in registration.EXEMPT:
        assert not registration.refused("GET", path, {}), path
    assert not registration.refused("PUT", "/api/settings/license", {})
    assert not registration.refused("GET", "/assets/index.js", {}) and not registration.refused("GET", "/zones", {})
    for path in ("/api/zones", "/api/settings/dns-server", "/api/auth/tokens", "/api/auth/password", "/api/dashboard", "/api/users"):
        assert registration.refused("GET", path, {}), path
    # Scripts with an app password are not the web console.
    assert not registration.refused("POST", "/api/zones", {"authorization": "Bearer dns1_abc"})


@pytest.fixture()
def api(db, monkeypatch):
    from fastapi.testclient import TestClient

    from dnsone import health
    from dnsone.api import create_app
    monkeypatch.setattr(health, "checks", lambda _db, cheap=False: [])
    monkeypatch.setattr(health, "overall", lambda _results: "ok")
    return TestClient(create_app())


def is_locked(response) -> bool:
    return response.status_code == 403 and response.json().get("code") == registration.CODE


def test_within_the_grace_the_console_works_with_a_banner_flag(db, api):
    grace_from(db, TODAY - timedelta(days=5))
    response = api.get("/api/zones")
    assert response.status_code == 401 and not is_locked(response)  # the usual answer: sign in
    user = SimpleNamespace(id=1, username="admin", name="Admin", email="", auth_source="local", totp_enabled=False,
                           max_zones=None, max_records=None, api_rate=None, role=SimpleNamespace(name="admin", zone_scope="all"))
    from dnsone.api.auth import me_payload
    me = me_payload(user, [], "csrf")
    assert me["registration"]["state"] == "grace" and me["registration"]["days_left"] == 25
    assert me["registration"]["url"] == "https://account.pingomni.com/buy?product=dnsone&plan=Community&period=12"


def test_after_the_grace_only_exempt_routes_answer(db, api):
    grace_from(db, TODAY - timedelta(days=31))
    for method, path in (("GET", "/api/zones"), ("POST", "/api/zones"), ("GET", "/api/settings/dns-server"), ("GET", "/api/dashboard"),
                         ("GET", "/api/queries"), ("DELETE", "/api/rpz/pause")):
        response = api.request(method, path)
        assert is_locked(response), (method, path)
        assert response.json()["registration"]["state"] == "locked" and response.headers["X-DNSOne-Version"]
    # Signing in, the session, the licence and the health check still answer as usual.
    assert api.get("/api/auth/me").status_code == 401
    assert api.get("/api/settings/license").status_code == 401
    assert api.put("/api/settings/license", json={"key": "x"}).status_code == 401
    assert api.get("/api/auth/oidc").json() == {"enabled": False, "label": ""}
    assert api.get("/api/health").status_code == 200
    # What machines call: dynamic DNS from routers, Prometheus, app passwords.
    assert api.get("/api/ddns/nic/update").text == "badauth"
    assert not is_locked(api.get("/api/metrics"))
    assert not is_locked(api.get("/api/zones", headers={"Authorization": "Bearer dns1_nope"}))


def test_storing_a_community_key_unlocks_without_a_restart(signer, db, api):
    grace_from(db, TODAY - timedelta(days=31))
    assert is_locked(api.get("/api/zones"))
    license.store(db, signer(TODAY + timedelta(days=365), **COMMUNITY))  # what PUT /api/settings/license does
    assert api.get("/api/zones").status_code == 401
    # Expired more than 30 days ago: locked again, with "renew".
    license.store(db, signer(TODAY - timedelta(days=31), lid="c0", **COMMUNITY))
    response = api.get("/api/zones")
    assert is_locked(response) and response.json()["registration"]["reason"] == "expired"


def test_dns_never_depends_on_registration(db, monkeypatch):
    """Locked or not, the Pro features, the query log and the DNS-facing modules behave as before."""
    import asyncio

    from dnsone import querylog
    grace_from(db, TODAY - timedelta(days=365))
    assert registration.current()["state"] == "locked"
    assert edition.name() == "community" and edition.features() == [] and not license.allows("legal")
    collector = querylog.Collector()
    monkeypatch.setattr(collector, "_read_privacy", lambda: None)
    asyncio.run(collector._reload_privacy())
    assert collector.syslog.state() is not None
    # Only the console's API reads the registration: no DNS-facing module, job or command imports it.
    package = Path(registration.__file__).parent
    for name in ("zonegen", "rpz", "runtime", "querylog", "cluster", "clusterjoin", "pbdns", "health", "stats", "protection",
                 "firewall", "transfers", "ddns", "legal", "cli", "activation"):
        imported = set()
        for node in ast.walk(ast.parse((package / f"{name}.py").read_text())):
            if isinstance(node, ast.ImportFrom):
                imported |= {node.module or ""} | {a.name for a in node.names}
            elif isinstance(node, ast.Import):
                imported |= {a.name for a in node.names}
        assert not any("registration" in i for i in imported), name
