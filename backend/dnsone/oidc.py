"""Single sign-on through Keycloak (OpenID Connect authorization code flow with PKCE).

1. /api/auth/oidc/login stores a state, a PKCE verifier and a nonce (oidc_logins) and redirects to
   Keycloak's authorization endpoint.
2. Keycloak sends the browser back to /api/auth/oidc/callback with a code; DNSOne exchanges it at
   the token endpoint (with the client secret and the verifier), checks the ID and access tokens'
   signatures against Keycloak's published keys (JWKS), issuer, audience, expiry and nonce.
3. The operator's DNSOne role comes from Keycloak roles (DNSONE_OIDC_ROLES, realm roles or roles of
   the dnsone client); without one of them, sign-in is refused. The account is found by Keycloak's
   user id (users.auth_source='oidc', external_id=sub), created on the first sign-in, and its name,
   email and role follow Keycloak at every sign-in. From there it is an ordinary DNSOne session.

Local accounts keep working beside SSO (break-glass access when Keycloak is down).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlencode

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import validation
from .config import Settings, get_settings
from .models import OidcLogin, Role, User
from .system import utcnow

LOGIN_MINUTES = 10
CLOCK_SKEW = 60
TIMEOUT = 10

_cache: dict[str, tuple[float, dict]] = {}


class OidcError(RuntimeError):
    """A sign-in that cannot go on; the message is shown on the sign-in page."""


def enabled(settings: Settings | None = None) -> bool:
    s = settings or get_settings()
    return bool(s.oidc_issuer and s.oidc_client_id and s.oidc_client_secret and s.public_url)


def redirect_uri(s: Settings) -> str:
    return f"{s.public_url}/api/auth/oidc/callback"


def _get_json(url: str, ttl: int, force: bool = False) -> dict:
    hit = _cache.get(url)
    if hit and not force and hit[0] > time.monotonic():
        return hit[1]
    try:
        response = httpx.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"Keycloak could not be reached ({exc.__class__.__name__}). Sign in with a local account, or try again.") from None
    _cache[url] = (time.monotonic() + ttl, data)
    return data


def discovery(s: Settings) -> dict:
    return _get_json(f"{s.oidc_issuer}/.well-known/openid-configuration", ttl=3600)


def _b64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _int(data: str) -> int:
    return int.from_bytes(_b64(data), "big")


def _public_key(jwk: dict):
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), ec.SECP256R1()).public_key()
    raise OidcError(f"Keycloak signs with an unsupported key type ({jwk.get('kty')}).")


def _find_key(s: Settings, kid: str) -> dict:
    url = discovery(s)["jwks_uri"]
    for force in (False, True):  # an unknown kid: Keycloak rotated its keys, fetch them again
        keys = _get_json(url, ttl=3600, force=force).get("keys", [])
        match = next((k for k in keys if k.get("kid") == kid and k.get("use", "sig") == "sig"), None)
        if match:
            return match
    raise OidcError("The token was signed with a key Keycloak does not publish.")


def verify_jwt(s: Settings, token: str) -> dict:
    """Checks a JWT's signature (RS256 or ES256) with Keycloak's keys, and its issuer and expiry."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(_b64(header_b64))
        claims = json.loads(_b64(payload_b64))
        signature = _b64(signature_b64)
    except (ValueError, TypeError):
        raise OidcError("Keycloak sent a malformed token.") from None
    alg = header.get("alg")
    key = _public_key(_find_key(s, header.get("kid", "")))
    signed = f"{header_b64}.{payload_b64}".encode()
    try:
        if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "ES256" and isinstance(key, ec.EllipticCurvePublicKey) and len(signature) == 64:
            der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            key.verify(der, signed, ec.ECDSA(hashes.SHA256()))
        else:
            raise OidcError(f"Keycloak signs tokens with {alg}; use RS256 or ES256.")
    except InvalidSignature:
        raise OidcError("The token's signature is not valid.") from None
    now = time.time()
    if claims.get("iss") != s.oidc_issuer:
        raise OidcError("The token comes from another issuer than DNSONE_OIDC_ISSUER.")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now - CLOCK_SKEW:
        raise OidcError("The token has expired; sign in again.")
    return claims


def start(db: Session, ip: str, settings: Settings | None = None) -> str:
    """Stores a pending sign-in; returns the Keycloak URL to send the browser to."""
    s = settings or get_settings()
    endpoint = discovery(s)["authorization_endpoint"]
    state, verifier, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(64), secrets.token_urlsafe(32)
    now = utcnow()
    db.execute(delete(OidcLogin).where(OidcLogin.expires_at < now))
    db.add(OidcLogin(state=state, verifier=verifier, nonce=nonce, ip=ip[:45], expires_at=now + timedelta(minutes=LOGIN_MINUTES)))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = {"response_type": "code", "client_id": s.oidc_client_id, "redirect_uri": redirect_uri(s), "scope": "openid profile email",
             "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
    return f"{endpoint}?{urlencode(query)}"


@dataclass
class Identity:
    sub: str
    username: str
    name: str
    email: str
    roles: set[str]
    id_token: str


def finish(db: Session, state: str, code: str, settings: Settings | None = None) -> Identity:
    """Exchanges the code Keycloak sent back; returns who signed in."""
    s = settings or get_settings()
    pending = db.get(OidcLogin, state) if state and len(state) <= 64 else None
    if pending is None or pending.expires_at < utcnow():
        raise OidcError("The sign-in expired or was already used. Start again.")
    db.delete(pending)
    db.flush()
    try:
        response = httpx.post(discovery(s)["token_endpoint"], timeout=TIMEOUT, data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(s), "code_verifier": pending.verifier,
            "client_id": s.oidc_client_id, "client_secret": s.oidc_client_secret})
        tokens = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"Keycloak could not be reached ({exc.__class__.__name__}).") from None
    if response.status_code != 200 or "id_token" not in tokens:
        raise OidcError(f"Keycloak refused the sign-in ({tokens.get('error_description') or tokens.get('error') or response.status_code}).")

    id_claims = verify_jwt(s, tokens["id_token"])
    aud = id_claims.get("aud")
    if s.oidc_client_id not in (aud if isinstance(aud, list) else [aud]):
        raise OidcError("The ID token was issued for another client.")
    if not secrets.compare_digest(str(id_claims.get("nonce", "")), pending.nonce):
        raise OidcError("The ID token does not belong to this sign-in.")
    roles: set[str] = set()
    if tokens.get("access_token"):
        access = verify_jwt(s, tokens["access_token"])
        if access.get("sub") != id_claims.get("sub"):
            raise OidcError("The access token is for another user.")
        roles |= set((access.get("realm_access") or {}).get("roles") or [])
        roles |= set(((access.get("resource_access") or {}).get(s.oidc_client_id) or {}).get("roles") or [])
    return Identity(sub=str(id_claims["sub"]), username=str(id_claims.get("preferred_username") or ""), name=str(id_claims.get("name") or ""),
                    email=str(id_claims.get("email") or ""), roles=roles, id_token=tokens["id_token"])


def role_for(identity: Identity, settings: Settings | None = None) -> str | None:
    s = settings or get_settings()
    return next((dnsone for keycloak, dnsone in s.oidc_roles if keycloak in identity.roles), None)


def upsert_user(db: Session, identity: Identity, settings: Settings | None = None) -> User:
    """The DNSOne account of a Keycloak user, created on the first sign-in; name, email and role follow Keycloak."""
    s = settings or get_settings()
    role_name = role_for(identity, s)
    if role_name is None:
        wanted = ", ".join(k for k, _ in s.oidc_roles)
        raise OidcError(f"Your SSO account has no DNSOne role ({wanted}). Ask an administrator to give you one in Keycloak.")
    role = db.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        raise OidcError(f"DNSONE_OIDC_ROLES maps to a role DNSOne does not have: {role_name}.")
    user = db.scalar(select(User).where(User.auth_source == "oidc", User.external_id == identity.sub))
    if user is None:
        user = User(username=_free_username(db, identity), auth_source="oidc", external_id=identity.sub, password_hash=None, role_id=role.id)
        db.add(user)
    elif not user.enabled:
        raise OidcError("This account is disabled in DNSOne. Ask an administrator.")
    user.role_id = role.id
    user.name = identity.name[:128]
    user.email = identity.email[:254]
    user.last_login_at = utcnow()
    db.flush()
    db.refresh(user)
    return user


def _free_username(db: Session, identity: Identity) -> str:
    """Keycloak's username, or with an .sso suffix if a local account already has it (never taken over)."""
    try:
        base = validation.username(identity.username)
    except validation.ValidationError:
        base = "sso-" + hashlib.sha256(identity.sub.encode()).hexdigest()[:12]
    for candidate in (base, f"{base}.sso"[:64], f"{base[:50]}.sso-{secrets.token_hex(3)}"):
        if db.scalar(select(User.id).where(User.username == candidate)) is None:
            return candidate
    raise OidcError("No free DNSOne username for this account.")


def logout_url(id_token: str | None, settings: Settings | None = None) -> str | None:
    """Keycloak's end-session URL, so signing out of DNSOne also ends the SSO session."""
    s = settings or get_settings()
    if not (enabled(s) and id_token):
        return None
    try:
        endpoint = discovery(s).get("end_session_endpoint")
    except OidcError:
        return None
    if not endpoint:
        return None
    return f"{endpoint}?{urlencode({'id_token_hint': id_token, 'post_logout_redirect_uri': f'{s.public_url}/', 'client_id': s.oidc_client_id})}"
