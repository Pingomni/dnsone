"""End-to-end: Settings -> Single sign-on against a real Keycloak (users, security, providers,
directories, events, email), password sign-in switched off, the emergency link, and moving local
accounts to Keycloak. Same Keycloak as test_sso.py, plus its admin-API secret:
    DNSONE_TEST_KEYCLOAK_ADMIN_SECRET_FILE=/path/to/admin-secret
"""

from __future__ import annotations

import os
import secrets

import pytest

from helpers import ENV
from test_sso import ISSUER, _browser, _error, _sign_in

pytestmark = [pytest.mark.skipif(not ENV, reason="DNSONE_TEST_ENV not set"),
              pytest.mark.skipif(not (ISSUER and os.environ.get("DNSONE_TEST_KEYCLOAK_ADMIN_SECRET_FILE")), reason="Keycloak admin API not set")]

RUN = secrets.token_hex(3)


@pytest.fixture()
def kc(client, monkeypatch):
    from dnsone import kcadmin, oidc
    from dnsone.config import get_settings
    monkeypatch.setenv("DNSONE_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("DNSONE_OIDC_CLIENT_SECRET", open(os.environ["DNSONE_TEST_KEYCLOAK_SECRET_FILE"]).read().strip())
    monkeypatch.setenv("DNSONE_PUBLIC_URL", "http://testserver")
    monkeypatch.setenv("DNSONE_KEYCLOAK_URL", ISSUER.rsplit("/realms/", 1)[0])
    monkeypatch.setenv("DNSONE_KEYCLOAK_ADMIN_CLIENT_SECRET", open(os.environ["DNSONE_TEST_KEYCLOAK_ADMIN_SECRET_FILE"]).read().strip())
    get_settings.cache_clear()
    oidc._cache.clear()
    kcadmin._token.clear()
    yield client
    monkeypatch.undo()
    get_settings.cache_clear()


def _admin_session(app):
    """alice (dnsone-admin) signed in through Keycloak, with her CSRF token."""
    browser, done, _ = _sign_in(app, "alice", "alice-sso-pass-1")
    assert done.headers["location"] == "/"
    browser.headers["X-CSRF-Token"] = browser.get("/api/auth/me").json()["csrf"]
    return browser


def test_operators_lifecycle(kc):
    name = f"op{RUN}"
    info = kc.get("/api/sso").json()
    assert info["enabled"] and info["admin_api"] and info["realm"] == "pingomni"

    created = kc.post("/api/sso/users", json={"username": name, "email": f"{name}@example.net", "first_name": "Op", "last_name": "Test",
                                               "role": "operator", "password": "Operator-pass-123", "temporary": False})
    assert created.status_code == 201, created.text
    kc_id = created.json()["id"]
    assert created.json()["temporary_password"] is None
    assert kc.post("/api/sso/users", json={"username": name, "role": "operator"}).status_code == 422  # taken
    assert kc.post("/api/sso/users", json={"username": f"x{RUN}", "role": "superuser"}).json()["errors"].get("role")

    row = next(r for r in kc.get("/api/sso/users", params={"q": name}).json()["rows"] if r["id"] == kc_id)
    assert row["role"] == "operator" and row["enabled"] and not row["two_factor"] and row["name"] == "Op Test"

    # The operator signs in through Keycloak with that role.
    op, done, _ = _sign_in(kc.app, name, "Operator-pass-123")
    assert done.headers["location"] == "/"
    assert op.get("/api/auth/me").json()["user"]["role"] == "operator"
    assert kc.get(f"/api/sso/users/{kc_id}").json()["sessions"], "Keycloak shows no session"

    # Role change applies at the next sign-in; disabling ends the DNSOne session at once.
    assert kc.patch(f"/api/sso/users/{kc_id}", json={"role": "viewer", "require_2fa": True}).json()["required_actions"] == ["CONFIGURE_TOTP"]
    assert kc.patch(f"/api/sso/users/{kc_id}", json={"enabled": False}).status_code == 200
    assert op.get("/api/auth/me").status_code == 401
    assert kc.patch(f"/api/sso/users/{kc_id}", json={"enabled": True, "require_2fa": False}).status_code == 200

    generated = kc.post(f"/api/sso/users/{kc_id}/password", json={}).json()["temporary_password"]
    assert generated and len(generated) >= 16
    assert kc.delete(f"/api/sso/users/{kc_id}/two-factor").json() == {"removed": 0}
    audit = kc.get("/api/audit", params={"action": "sso.user"}).json()["rows"]
    assert {"sso.user_created", "sso.user_updated"} <= {a["action"] for a in audit}
    assert "Operator-pass-123" not in str(audit) and generated not in str(audit)

    assert kc.delete(f"/api/sso/users/{kc_id}").status_code == 200
    assert kc.get(f"/api/sso/users/{kc_id}").status_code == 404


def test_admin_cannot_lock_themselves_out(kc):
    alice = _admin_session(kc.app)
    me = next(r for r in alice.get("/api/sso/users", params={"q": "alice"}).json()["rows"] if r["username"] == "alice")
    assert me["self"] is True
    assert alice.patch(f"/api/sso/users/{me['id']}", json={"enabled": False}).status_code == 422
    assert alice.patch(f"/api/sso/users/{me['id']}", json={"role": "viewer"}).status_code == 422
    assert alice.delete(f"/api/sso/users/{me['id']}").status_code == 422


def test_security_policy(kc):
    before = kc.get("/api/sso/security").json()
    try:
        saved = kc.put("/api/sso/security", json={**before, "password": {**before["password"], "length": 14, "digits": 1},
                                                   "brute_force": {"enabled": True, "max_failures": 4, "lock_minutes": 20},
                                                   "sessions": {"idle_minutes": 45, "max_hours": 10}, "remember_me": True,
                                                   "two_factor_required": True})
        assert saved.status_code == 200, saved.text
        s = saved.json()
        assert s["password"]["length"] == 14 and s["password"]["digits"] == 1 and s["two_factor_required"] is True
        assert s["brute_force"]["max_failures"] == 4 and s["brute_force"]["lock_minutes"] == 20 and s["sessions"] == {"idle_minutes": 45, "max_hours": 10}
        short = kc.post("/api/sso/users", json={"username": f"short{RUN}", "role": "viewer", "password": "Short-1", "temporary": False})
        assert short.status_code == 422 and "password" in short.json()["errors"]
        # Keycloak created the user before the password was refused: clean up.
        leftover = [r for r in kc.get("/api/sso/users", params={"q": f"short{RUN}"}).json()["rows"]]
        for r in leftover:
            kc.delete(f"/api/sso/users/{r['id']}")
        assert kc.put("/api/sso/security", json={**before, "password": {"length": 3}}).status_code == 422
    finally:
        kc.put("/api/sso/security", json=before)


def test_providers_directories_events_email(kc):
    added = kc.post("/api/sso/providers", json={"type": "google", "client_id": "123.apps.googleusercontent.com", "client_secret": "s3cret"})
    assert added.status_code == 201, added.text
    assert added.json()["redirect_uri"] == "http://testserver/auth/realms/pingomni/broker/google/endpoint"
    listed = kc.get("/api/sso/providers").json()["providers"]
    assert any(p["alias"] == "google" and p["enabled"] for p in listed)
    assert kc.patch("/api/sso/providers/google", params={"enabled": False}).status_code == 200
    assert not next(p for p in kc.get("/api/sso/providers").json()["providers"] if p["alias"] == "google")["enabled"]
    assert kc.delete("/api/sso/providers/google").status_code == 200
    assert kc.post("/api/sso/providers", json={"type": "oidc", "alias": "corp", "client_id": "a", "client_secret": "b",
                                                "discovery_url": "http://insecure.example"}).json()["errors"].get("discovery_url")

    refused = kc.post("/api/sso/ldap/test", json={"url": "ldap://127.0.0.1:9", "bind_dn": "CN=svc,DC=x", "bind_password": "p", "users_dn": "DC=x"})
    assert refused.status_code == 422 and "url" in refused.json()["errors"]
    assert kc.post("/api/sso/ldap/test", json={"url": "http://x", "users_dn": "DC=x"}).json()["errors"].get("url")
    assert kc.get("/api/sso/ldap").json() == {"directories": []}

    _sign_in(kc.app, "alice", "alice-sso-pass-1")
    events = kc.get("/api/sso/events", params={"type": "LOGIN"}).json()["rows"]
    assert any(e["username"] == "alice" and e["type"] == "LOGIN" for e in events)

    saved = kc.put("/api/sso/email", json={"host": "smtp.example.net", "port": 587, "security": "starttls", "from": "no-reply@example.net", "from_name": "DNSOne"})
    assert saved.status_code == 200 and saved.json()["host"] == "smtp.example.net" and saved.json()["from"] == "no-reply@example.net"
    test = kc.put("/api/sso/email", json={"host": "127.0.0.1", "port": 9, "security": "none", "from": "a@example.net", "test_to": "b@example.net"})
    assert test.status_code == 422 and "Sending failed" in test.json()["message"]
    assert kc.put("/api/sso/email", json={"host": ""}).json()["host"] == ""


def test_password_sign_in_off_and_emergency_link(kc, monkeypatch):
    from dnsone import ssoadmin
    from dnsone.config import get_settings
    from dnsone.db import session_scope
    from helpers import PASSWORD
    monkeypatch.setenv("DNSONE_LOCAL_LOGIN", "0")
    get_settings.cache_clear()
    assert kc.get("/api/auth/oidc").json()["local_login"] is False
    browser = _browser(kc.app)
    refused = browser.post("/api/auth/login", json={"username": "admin", "password": PASSWORD})
    assert refused.status_code == 403 and "single sign-on" in refused.json()["message"]

    with session_scope() as db:
        link = ssoadmin.create_emergency_link(db, "admin")
    path = link.split("http://testserver", 1)[1]
    used = browser.get(path)
    assert used.status_code == 303 and used.headers["location"] == "/"
    assert browser.get("/api/auth/me").json()["user"]["username"] == "admin"
    assert "not valid" in _error(_browser(kc.app).get(path))  # single use
    with session_scope() as db:
        expired = ssoadmin.create_emergency_link(db, "admin")
        from dnsone.models import Setting
        db.flush()
        row = db.get(Setting, ssoadmin.EMERGENCY_KEY)
        row.value = {**row.value, "expires": "2000-01-01T00:00:00"}
    assert "not valid" in _error(_browser(kc.app).get(expired.split("http://testserver", 1)[1]))


def test_move_local_accounts_to_keycloak(kc):
    before = kc.get("/api/sso").json()["local_accounts"]
    assert {"admin", "viewer"} <= set(before)
    moved = kc.post("/api/sso/migrate-local-users").json()["moved"]
    assert {m["username"] for m in moved} == set(before)
    assert kc.get("/api/sso").json()["local_accounts"] == []
    users = {u["username"]: u for u in kc.get("/api/users").json()["rows"]}
    assert users["admin"]["auth_source"] == "oidc" and users["viewer"]["auth_source"] == "oidc"
    kc_users = {r["username"]: r for r in kc.get("/api/sso/users", params={"q": "viewer"}).json()["rows"]}
    assert kc_users["viewer"]["role"] == "viewer"
    # A fresh account got a temporary password, which Keycloak makes them change at the first sign-in.
    fresh = [m for m in moved if not m["linked"]]
    for m in fresh:
        assert m["temporary_password"] and "UPDATE_PASSWORD" in next(
            r for r in kc.get("/api/sso/users", params={"q": m["username"]}).json()["rows"] if r["username"] == m["username"])["required_actions"]
