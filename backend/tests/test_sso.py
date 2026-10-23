"""End-to-end: single sign-on through a real Keycloak (authorization code + PKCE).

Needs the test stack (test_integration.py) and a Keycloak configured with ops/keycloak-realm for
PUBLIC_URL=http://testserver, with users alice (dnsone-admin), bob (no DNSOne role) and carol
(dnsone-viewer), each with password <name>-sso-pass-1:
    DNSONE_TEST_KEYCLOAK=http://127.0.0.1:8180/auth/realms/pingomni
    DNSONE_TEST_KEYCLOAK_SECRET_FILE=/path/to/client-secret
"""

from __future__ import annotations

import html
import os
import re
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from helpers import ENV

ISSUER = os.environ.get("DNSONE_TEST_KEYCLOAK", "")
pytestmark = [pytest.mark.skipif(not ENV, reason="DNSONE_TEST_ENV not set"),
              pytest.mark.skipif(not ISSUER, reason="DNSONE_TEST_KEYCLOAK not set")]


@pytest.fixture()
def sso(client, monkeypatch):
    from dnsone import oidc
    from dnsone.config import get_settings
    monkeypatch.setenv("DNSONE_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("DNSONE_OIDC_CLIENT_ID", "dnsone")
    monkeypatch.setenv("DNSONE_OIDC_CLIENT_SECRET", open(os.environ["DNSONE_TEST_KEYCLOAK_SECRET_FILE"]).read().strip())
    monkeypatch.setenv("DNSONE_PUBLIC_URL", "http://testserver")
    get_settings.cache_clear()
    oidc._cache.clear()
    yield client
    monkeypatch.undo()
    get_settings.cache_clear()


def _browser(app):
    from fastapi.testclient import TestClient
    return TestClient(app, follow_redirects=False)


def _sign_in(app, username: str, password: str):
    """Clicks "Sign in with SSO", fills in Keycloak's form; returns (DNSOne client, callback response)."""
    dnsone = _browser(app)
    start = dnsone.get("/api/auth/oidc/login")
    assert start.status_code == 303, start.text
    keycloak = httpx.Client(follow_redirects=False, timeout=10)
    page = keycloak.get(start.headers["location"])
    assert page.status_code == 200, page.text[:300]
    action = html.unescape(re.search(r'<form[^>]+id="kc-form-login"[^>]+action="([^"]+)"', page.text).group(1))
    # Keycloak marks its cookies Secure; the test Keycloak is plain http, where httpx would not send them.
    cookies = "; ".join(f"{c.name}={c.value}" for c in keycloak.cookies.jar)
    back = keycloak.post(action, headers={"cookie": cookies}, data={"username": username, "password": password, "credentialId": ""})
    assert back.status_code == 302, back.text[:300]
    callback = urlsplit(back.headers["location"])
    assert f"{callback.scheme}://{callback.netloc}{callback.path}" == "http://testserver/api/auth/oidc/callback"
    return dnsone, dnsone.get(f"{callback.path}?{callback.query}"), callback.query


def _error(response) -> str:
    assert response.status_code == 303
    location = urlsplit(response.headers["location"])
    return parse_qs(location.query).get("sso_error", [""])[0]


def test_sso_status_off_by_default(client):
    assert client.get("/api/auth/oidc").json()["enabled"] is False
    off = _browser(client.app).get("/api/auth/oidc/login")
    assert "not configured" in _error(off)


def test_sso_admin_sign_in_and_out(sso):
    assert sso.get("/api/auth/oidc").json() == {"enabled": True, "label": "Sign in with SSO"}
    browser, done, query = _sign_in(sso.app, "alice", "alice-sso-pass-1")
    assert done.status_code == 303 and done.headers["location"] == "/"
    me = browser.get("/api/auth/me").json()
    assert me["user"]["username"] == "alice" and me["user"]["auth_source"] == "oidc" and me["user"]["role"] == "admin"
    assert me["user"]["email"] == "alice@example.net" and "users.manage" in me["permissions"]

    # The code and state are single-use.
    replay = browser.get(f"/api/auth/oidc/callback?{query}")
    assert "expired or was already used" in _error(replay)
    # SSO accounts have no DNSOne password or two-factor.
    browser.headers["X-CSRF-Token"] = me["csrf"]
    assert browser.post("/api/auth/password", json={"current_password": "x", "new_password": "y" * 12}).status_code == 400

    out = browser.post("/api/auth/logout").json()
    assert out["redirect"].startswith(f"{ISSUER}/protocol/openid-connect/logout?id_token_hint=")
    assert browser.get("/api/auth/me").status_code == 401
    audit = sso.get("/api/audit", params={"actor": "alice", "action": "auth.login"}).json()["rows"]
    assert audit and audit[0]["payload"] == {"method": "sso"}


def test_sso_without_role_is_refused(sso):
    browser, refused, _ = _sign_in(sso.app, "bob", "bob-sso-pass-1")
    assert "no DNSOne role" in _error(refused)
    assert browser.get("/api/auth/me").status_code == 401
    assert all(u["username"] != "bob" for u in sso.get("/api/users").json()["rows"])


def test_sso_never_takes_over_a_local_account(sso):
    from dnsone import security
    from dnsone.db import session_scope
    from dnsone.models import Role, User
    with session_scope() as db:
        if db.query(User).filter_by(username="carol").first() is None:
            viewer = db.query(Role).filter_by(name="viewer").one()
            db.add(User(username="carol", name="Local Carol", role_id=viewer.id, password_hash=security.hash_password("local-carol-pass-1")))
    browser, done, _ = _sign_in(sso.app, "carol", "carol-sso-pass-1")
    assert done.headers["location"] == "/"
    me = browser.get("/api/auth/me").json()["user"]
    assert me["username"] == "carol.sso" and me["role"] == "viewer" and me["auth_source"] == "oidc"
    # Signing in again finds the same account (by Keycloak's user id, not the name).
    again, _, _ = _sign_in(sso.app, "carol", "carol-sso-pass-1")
    assert again.get("/api/auth/me").json()["user"]["id"] == me["id"]


def test_sso_rejects_forged_callbacks(sso):
    browser = _browser(sso.app)
    assert "expired or was already used" in _error(browser.get("/api/auth/oidc/callback?state=made-up&code=x"))
    assert "cancelled" in _error(browser.get("/api/auth/oidc/callback?error=access_denied"))
    # A real state with a code Keycloak never issued.
    start = browser.get("/api/auth/oidc/login")
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    assert "refused" in _error(browser.get(f"/api/auth/oidc/callback?state={state}&code=forged"))
