"""Registering the licence's server with the PingOmni account portal (activation.py). A fake portal and settings store; no services needed."""
from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dnsone import activation, config, license
from dnsone.models import Setting


class FakeDB:
    """The two Setting rows activation.py reads and writes."""

    def __init__(self):
        self.rows: dict[str, Setting] = {}

    def get(self, _model, name):
        return self.rows.get(name)

    def add(self, row):
        self.rows[row.name] = row

    def query(self, _model):
        db = self

        class Q:
            def filter(self, clause):
                self.name = clause.right.value
                return self

            def delete(self):
                db.rows.pop(self.name, None)

        return Q()


class Portal:
    """A fake account portal: records the calls and answers what the test sets."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.answers: dict[str, httpx.Response] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        self.calls.append((request.url.path, body))
        return self.answers.get(request.url.path, httpx.Response(500))

    def client(self) -> httpx.Client:
        return httpx.Client(base_url="https://account.test", transport=httpx.MockTransport(self.handler))


@pytest.fixture()
def keys(monkeypatch):
    signing = Ed25519PrivateKey.generate()
    public = base64.b64encode(signing.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    monkeypatch.setattr(license, "PUBLIC_KEYS", [public])

    def issue(expires: date, lid: str = "lic1") -> str:
        payload = json.dumps({"v": 1, "id": lid, "customer": "Test ISP", "issued": "2026-01-01", "expires": expires.isoformat(), "features": ["all"]}).encode()
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
        return f"DNSONE1.{b64(payload)}.{b64(signing.sign(payload))}"

    return issue


@pytest.fixture()
def env(monkeypatch, tmp_path):
    machine = tmp_path / "machine-id"
    machine.write_text("0123456789abcdef0123456789abcdef\n")
    monkeypatch.setenv("DNSONE_DATABASE_URL", "mysql+pymysql://test:test@127.0.0.1/test")
    config.get_settings.cache_clear()
    settings = replace(config.get_settings(), account_url="https://account.test", machine_id_file=machine, node_name="dns1", role="primary")
    config.get_settings.cache_clear()
    monkeypatch.setattr(activation, "get_settings", lambda: settings)
    return settings


def install(db: FakeDB, key: str) -> None:
    db.add(Setting(name=license.KEY, value={"key": key}))


def test_a_new_key_registers_then_checks_in_twice_a_day(keys, env):
    db, portal = FakeDB(), Portal()
    install(db, keys(date.today() + timedelta(days=365)))
    portal.answers["/api/v1/activate"] = httpx.Response(200, json={"token": "t" * 64, "lease_until": "2026-12-01"})
    state = activation.run(db, client=portal.client())
    assert state["status"] == "registered" and state["token"] == "t" * 64 and state["hostname"] == "dns1"
    path, body = portal.calls[0]
    assert path == "/api/v1/activate" and body["hostname"] == "dns1" and len(body["fingerprint"]) == 64

    # Not due again for 12 hours: nothing is sent.
    activation.run(db, client=portal.client())
    assert len(portal.calls) == 1
    # Once due, a check-in with the token.
    db.rows[activation.KEY].value["last_attempt"] = (datetime.now(timezone.utc) - timedelta(hours=13)).isoformat()
    portal.answers["/api/v1/check-in"] = httpx.Response(200, json={"lease_until": "2026-12-02"})
    state = activation.run(db, client=portal.client())
    assert portal.calls[-1][0] == "/api/v1/check-in" and state["status"] == "registered" and state["lease_until"] == "2026-12-02"


def test_an_updated_key_from_the_portal_is_installed(keys, env):
    db, portal = FakeDB(), Portal()
    # The portal signs a renewed key (or one with more servers) with a new id.
    old, new = keys(date.today() + timedelta(days=10)), keys(date.today() + timedelta(days=375), lid="lic2")
    install(db, old)
    portal.answers["/api/v1/activate"] = httpx.Response(200, json={"token": "t" * 64, "key": new})
    state = activation.run(db, client=portal.client())
    assert db.rows[license.KEY].value["key"] == new and state["license_id"] == "lic2"
    # Not due again: the new key does not set off another registration.
    activation.run(db, client=portal.client())
    assert len(portal.calls) == 1
    # A key that is not signed by PingOmni is never taken.
    portal.answers["/api/v1/check-in"] = httpx.Response(200, json={"key": "DNSONE1.e30.AAAA"})
    activation.run(db, force=True, client=portal.client())
    assert db.rows[license.KEY].value["key"] == new


def test_refusals_and_outages_are_reported_not_enforced(keys, env):
    db, portal = FakeDB(), Portal()
    key = keys(date.today() + timedelta(days=365))
    install(db, key)
    portal.answers["/api/v1/activate"] = httpx.Response(409, json={"error": "in_use", "message": "This licence is active on another server (dns2)."})
    state = activation.run(db, client=portal.client())
    assert state["status"] == "in_use" and "dns2" in state["message"]
    assert db.rows[license.KEY].value["key"] == key  # the key stays: report only

    def down(_request):
        raise httpx.ConnectError("no route")

    state = activation.run(db, force=True, client=httpx.Client(base_url="https://account.test", transport=httpx.MockTransport(down)))
    assert state["status"] == "unreachable"
    assert activation.public(db)["status"] == "unreachable"


def test_removing_the_key_releases_the_server(keys, env):
    db, portal = FakeDB(), Portal()
    install(db, keys(date.today() + timedelta(days=365)))
    portal.answers["/api/v1/activate"] = httpx.Response(200, json={"token": "t" * 64})
    activation.run(db, client=portal.client())
    db.rows.pop(license.KEY)
    portal.answers["/api/v1/deactivate"] = httpx.Response(200, json={"released": True})
    activation.run(db, client=portal.client())
    assert portal.calls[-1][0] == "/api/v1/deactivate" and activation.KEY not in db.rows


def test_off_and_replicas_send_nothing(keys, env, monkeypatch):
    db, portal = FakeDB(), Portal()
    install(db, keys(date.today() + timedelta(days=365)))
    for changed in ({"account_url": ""}, {"role": "replica"}):
        monkeypatch.setattr(activation, "get_settings", lambda c=changed: replace(env, **c))
        activation.run(db, client=portal.client())
    assert portal.calls == []
