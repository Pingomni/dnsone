"""Keycloak's admin REST API, used by Settings -> Single sign-on.

DNSOne signs in to Keycloak as the "dnsone-admin-api" service account (client credentials, created
by ops/keycloak-realm with only the realm-management roles it needs) and talks to Keycloak directly
on DNSONE_KEYCLOAK_URL, not through nginx. Every call is scoped to one realm (DNSONE_KEYCLOAK_REALM).
"""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx

from .config import Settings, get_settings

TIMEOUT = 15


class KeycloakError(RuntimeError):
    """A call Keycloak refused or could not answer; `status` is Keycloak's HTTP status (0: unreachable)."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


_token: dict[str, Any] = {}
_lock = threading.Lock()


def configured(settings: Settings | None = None) -> bool:
    s = settings or get_settings()
    return bool(s.keycloak_url and s.keycloak_realm and s.keycloak_admin_client_secret)


def _access_token(s: Settings) -> str:
    with _lock:
        if _token.get("value") and _token["expires"] > time.monotonic() + 30 and _token.get("for") == s.keycloak_admin_client_id:
            return _token["value"]
        try:
            response = httpx.post(f"{s.keycloak_url}/realms/{s.keycloak_realm}/protocol/openid-connect/token", timeout=TIMEOUT, data={
                "grant_type": "client_credentials", "client_id": s.keycloak_admin_client_id, "client_secret": s.keycloak_admin_client_secret})
        except httpx.HTTPError as exc:
            raise KeycloakError(0, f"Keycloak could not be reached at {s.keycloak_url} ({exc.__class__.__name__}).") from None
        if response.status_code != 200:
            raise KeycloakError(response.status_code, "DNSOne cannot sign in to Keycloak's admin API: check DNSONE_KEYCLOAK_ADMIN_CLIENT_SECRET.")
        data = response.json()
        _token.update(value=data["access_token"], expires=time.monotonic() + int(data.get("expires_in", 60)), **{"for": s.keycloak_admin_client_id})
        return _token["value"]


def _message(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return response.text[:300] or f"HTTP {response.status_code}"
    if isinstance(data, dict):
        return str(data.get("errorMessage") or data.get("error_description") or data.get("error") or data)[:300]
    return str(data)[:300]


def call(method: str, path: str, json: Any = None, params: dict | None = None, settings: Settings | None = None) -> Any:
    """One admin API call under /admin/realms/<realm>. Returns the JSON body, the new id for a 201, or None."""
    s = settings or get_settings()
    if not configured(s):
        raise KeycloakError(0, "Keycloak's admin API is not configured (DNSONE_KEYCLOAK_ADMIN_CLIENT_SECRET).")
    url = f"{s.keycloak_url}/admin/realms/{s.keycloak_realm}{path}"
    for attempt in (1, 2):
        headers = {"Authorization": f"Bearer {_access_token(s)}"}
        try:
            response = httpx.request(method, url, json=json, params=params, headers=headers, timeout=TIMEOUT)
        except httpx.HTTPError as exc:
            raise KeycloakError(0, f"Keycloak could not be reached ({exc.__class__.__name__}).") from None
        if response.status_code == 401 and attempt == 1:
            _token.clear()  # expired or revoked: get a new token once
            continue
        break
    if response.status_code >= 400:
        raise KeycloakError(response.status_code, _message(response))
    if response.status_code == 201:
        location = response.headers.get("location", "")
        return location.rstrip("/").rsplit("/", 1)[-1] or None
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        return response.text


def get(path: str, **params) -> Any:
    return call("GET", path, params={k: v for k, v in params.items() if v not in (None, "")})


def realm() -> dict:
    return call("GET", "")


def update_realm(changes: dict) -> None:
    call("PUT", "", json=changes)
