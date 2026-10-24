"""Single sign-on with any OpenID Connect provider (Settings → Single sign-on).

Works with Google Workspace, Microsoft Entra ID, Okta, Authentik, Keycloak, Zitadel, Auth0 and any
other provider that publishes /.well-known/openid-configuration. Nothing is installed on the server.

1. /api/auth/oidc/login stores a state, a PKCE verifier and a nonce (oidc_logins) and sends the browser
   to the provider's authorization endpoint.
2. The provider sends it back to /api/auth/oidc/callback with a code. DNSOne exchanges it at the token
   endpoint (client secret, PKCE verifier), checks the ID token's signature against the provider's
   published keys (JWKS; RS*, PS* or ES* algorithms), its issuer, audience, expiry and nonce, and adds
   the userinfo endpoint's claims.
3. The account: the one linked to the provider's subject (users.auth_source='oidc', external_id=sub);
   else an invited account (single sign-on, not linked yet) with the same verified email, which is
   linked now; else, if allowed, a new account. A local account is never taken over.
4. The role: the first role mapping whose claim value the user has (e.g. groups contains "dns-admins"
   → admin). Without a match a linked account keeps its role, and a new one gets the default role, or
   is refused if there is none.

Local accounts keep working beside single sign-on (break-glass access when the provider is down).
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from datetime import timedelta
from urllib.parse import urlencode, urlparse

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import validation
from .models import OidcLogin, Role, Setting, User
from .system import utcnow

KEY = "sso.oidc"
LOGIN_MINUTES = 10
CLOCK_SKEW = 120
TIMEOUT = 10
DEFAULT = {
    "enabled": False, "issuer": "", "client_id": "", "client_secret": "", "label": "Sign in with single sign-on",
    "scopes": "openid profile email", "public_url": "", "role_claim": "groups", "role_map": [], "default_role": "",
    "auto_create": True, "allowed_domains": [], "username_claim": "preferred_username", "end_session": True,
}
_HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
_cache: dict[str, tuple[float, dict]] = {}


class OidcError(RuntimeError):
    """A sign-in that cannot go on; the message is shown on the sign-in page."""


# --------------------------------------------------------------------------- settings


def get(db: Session) -> dict:
    row = db.get(Setting, KEY)
    return {**DEFAULT, **(row.value if row else {})}


def public(cfg: dict) -> dict:
    out = {k: v for k, v in cfg.items() if k != "client_secret"}
    out["client_secret_set"] = bool(cfg["client_secret"])
    out["redirect_uri"] = redirect_uri(cfg) if cfg["public_url"] else ""
    return out


def ready(cfg: dict) -> bool:
    return bool(cfg["enabled"] and cfg["issuer"] and cfg["client_id"] and cfg["public_url"])


def _url(raw: str, field: str) -> str:
    value = raw.strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        if not (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1")):
            raise validation.ValidationError(field, "Enter an https:// address.")
    return value


def store(db: Session, data: dict, roles: set[str]) -> dict:
    current = get(db)
    out = dict(DEFAULT)
    out["enabled"] = bool(data.get("enabled"))
    for key in ("issuer", "public_url"):
        raw = str(data.get(key) or "").strip()
        out[key] = _url(raw, key) if raw else ""
    out["client_id"] = str(data.get("client_id") or "").strip()[:255]
    secret = str(data.get("client_secret") or "")
    out["client_secret"] = secret.strip() if secret.strip() else current["client_secret"]
    if data.get("clear_client_secret"):
        out["client_secret"] = ""
    out["label"] = str(data.get("label") or DEFAULT["label"]).strip()[:64]
    scopes = " ".join(str(data.get("scopes") or DEFAULT["scopes"]).split())
    if "openid" not in scopes.split():
        raise validation.ValidationError("scopes", "The scopes must include openid.")
    out["scopes"] = scopes[:255]
    for key, default in (("role_claim", "groups"), ("username_claim", "preferred_username")):
        value = str(data.get(key) or default).strip()
        if not value.replace(".", "").replace("_", "").replace("-", "").replace(":", "").replace("/", "").isalnum():
            raise validation.ValidationError(key, "Enter a claim name such as groups, roles or realm_access.roles.")
        out[key] = value[:128]
    mapping = []
    for i, m in enumerate(data.get("role_map") or []):
        claim, role = str(m.get("value") or "").strip(), str(m.get("role") or "").strip()
        if not claim and not role:
            continue
        if not claim:
            raise validation.ValidationError(f"role_map.{i}.value", "Enter the group or role the provider sends.")
        if role not in roles:
            raise validation.ValidationError(f"role_map.{i}.role", "Choose a DNSOne role.")
        mapping.append({"value": claim[:255], "role": role})
    out["role_map"] = mapping
    default_role = str(data.get("default_role") or "").strip()
    if default_role and default_role not in roles:
        raise validation.ValidationError("default_role", "Choose a DNSOne role, or none.")
    out["default_role"] = default_role
    out["auto_create"] = bool(data.get("auto_create", True))
    out["end_session"] = bool(data.get("end_session", True))
    domains = []
    for raw in data.get("allowed_domains") or []:
        value = str(raw).strip().lower().lstrip("@")
        if value:
            domains.append(validation.zone_name(value, "allowed_domains"))
    out["allowed_domains"] = domains
    if out["enabled"]:
        for key, message in (("issuer", "Enter the provider's issuer URL."), ("client_id", "Enter the client id DNSOne is registered with."),
                             ("public_url", "Enter the console's address, e.g. https://dns.isp.example.")):
            if not out[key]:
                raise validation.ValidationError(key, message)
    row = db.get(Setting, KEY)
    if row is None:
        db.add(Setting(name=KEY, value=out))
    else:
        row.value = out
    return out


def redirect_uri(cfg: dict) -> str:
    return f"{cfg['public_url']}/api/auth/oidc/callback"


# --------------------------------------------------------------------------- provider metadata and tokens


def _get_json(url: str, ttl: int, force: bool = False) -> dict:
    hit = _cache.get(url)
    if hit and not force and hit[0] > time.monotonic():
        return hit[1]
    try:
        response = httpx.get(url, timeout=TIMEOUT, follow_redirects=True)
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"The sign-in provider could not be reached ({exc.__class__.__name__}). Sign in with a local account, or try again.") from None
    if not isinstance(data, dict):
        raise OidcError("The sign-in provider sent something unexpected.")
    _cache[url] = (time.monotonic() + ttl, data)
    return data


def discovery(cfg: dict, force: bool = False) -> dict:
    data = _get_json(f"{cfg['issuer']}/.well-known/openid-configuration", ttl=3600, force=force)
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
        if not data.get(key):
            raise OidcError(f"The provider's configuration has no {key}.")
    return data


def _b64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _int(data: str) -> int:
    return int.from_bytes(_b64(data), "big")


def _public_key(jwk: dict):
    if jwk.get("kty") == "RSA":
        return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
    if jwk.get("kty") == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}.get(jwk.get("crv"))
        if curve is not None:
            return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), curve).public_key()
    raise OidcError(f"The provider signs with an unsupported key type ({jwk.get('kty')} {jwk.get('crv', '')}).")


def _find_key(cfg: dict, kid: str | None, alg: str) -> dict:
    url = discovery(cfg)["jwks_uri"]
    for force in (False, True):  # an unknown kid: the provider rotated its keys, fetch them again
        keys = [k for k in _get_json(url, ttl=3600, force=force).get("keys", []) if k.get("use", "sig") == "sig"]
        if kid:
            match = next((k for k in keys if k.get("kid") == kid), None)
        else:
            family = "RSA" if alg[:2] in ("RS", "PS") else "EC"
            same = [k for k in keys if k.get("kty") == family]
            match = same[0] if len(same) == 1 else None
        if match:
            return match
    raise OidcError("The token was signed with a key the provider does not publish.")


def verify_jwt(cfg: dict, token: str, issuer: str) -> dict:
    """Checks a JWT's signature with the provider's keys, and its issuer and expiry."""
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(_b64(header_b64))
        claims = json.loads(_b64(payload_b64))
        signature = _b64(signature_b64)
    except (ValueError, TypeError):
        raise OidcError("The provider sent a malformed token.") from None
    alg = str(header.get("alg", ""))
    if alg[:2] not in ("RS", "PS", "ES") or alg[2:] not in _HASHES:
        raise OidcError(f"The provider signs tokens with {alg or 'no algorithm'}; DNSOne accepts RS256/384/512, PS256/384/512 and ES256/384/512.")
    key = _public_key(_find_key(cfg, header.get("kid"), alg))
    signed = f"{header_b64}.{payload_b64}".encode()
    digest = _HASHES[alg[2:]]()
    try:
        if alg.startswith("RS") and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, padding.PKCS1v15(), digest)
        elif alg.startswith("PS") and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size), digest)
        elif alg.startswith("ES") and isinstance(key, ec.EllipticCurvePublicKey) and len(signature) % 2 == 0:
            half = len(signature) // 2
            der = encode_dss_signature(int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big"))
            key.verify(der, signed, ec.ECDSA(digest))
        else:
            raise OidcError(f"The token's algorithm {alg} does not match the provider's key.")
    except InvalidSignature:
        raise OidcError("The token's signature is not valid.") from None
    now = time.time()
    if claims.get("iss") != issuer:
        raise OidcError("The token comes from another issuer than the one configured.")
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] < now - CLOCK_SKEW:
        raise OidcError("The token has expired; sign in again.")
    if isinstance(claims.get("iat"), (int, float)) and claims["iat"] > now + CLOCK_SKEW:
        raise OidcError("The token was issued in the future: check the server's clock.")
    return claims


def start(db: Session, cfg: dict, ip: str) -> str:
    """Stores a pending sign-in; returns the provider URL to send the browser to."""
    endpoint = discovery(cfg)["authorization_endpoint"]
    state, verifier, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(64), secrets.token_urlsafe(32)
    now = utcnow()
    db.execute(delete(OidcLogin).where(OidcLogin.expires_at < now))
    db.add(OidcLogin(state=state, verifier=verifier, nonce=nonce, ip=ip[:45], expires_at=now + timedelta(minutes=LOGIN_MINUTES)))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = {"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": redirect_uri(cfg), "scope": cfg["scopes"],
             "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}{urlencode(query)}"


@dataclass
class Identity:
    sub: str
    claims: dict
    id_token: str

    @property
    def email(self) -> str:
        return str(self.claims.get("email") or "").strip().lower()

    @property
    def email_verified(self) -> bool:
        # Providers that do not send the claim (e.g. Entra ID) vouch for the address they send.
        return self.claims.get("email_verified") not in (False, "false")


def finish(db: Session, cfg: dict, state: str, code: str) -> Identity:
    """Exchanges the code the provider sent back; returns who signed in."""
    pending = db.get(OidcLogin, state) if state and len(state) <= 64 else None
    if pending is None or pending.expires_at < utcnow():
        raise OidcError("The sign-in expired or was already used. Start again.")
    db.delete(pending)
    db.flush()
    meta = discovery(cfg)
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(cfg), "code_verifier": pending.verifier}
    auth = None
    methods = meta.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
    if cfg["client_secret"] and "client_secret_basic" in methods:
        auth = (cfg["client_id"], cfg["client_secret"])
    else:
        data["client_id"] = cfg["client_id"]
        if cfg["client_secret"]:
            data["client_secret"] = cfg["client_secret"]
    try:
        response = httpx.post(meta["token_endpoint"], data=data, auth=auth, timeout=TIMEOUT, headers={"Accept": "application/json"})
        tokens = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"The sign-in provider could not be reached ({exc.__class__.__name__}).") from None
    if response.status_code != 200 or not isinstance(tokens, dict) or "id_token" not in tokens:
        reason = tokens.get("error_description") or tokens.get("error") if isinstance(tokens, dict) else None
        raise OidcError(f"The provider refused the sign-in ({reason or response.status_code}).")

    claims = verify_jwt(cfg, tokens["id_token"], meta["issuer"])
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if cfg["client_id"] not in audiences:
        raise OidcError("The ID token was issued for another client.")
    if len(audiences) > 1 and claims.get("azp") not in (None, cfg["client_id"]):
        raise OidcError("The ID token was issued for another client.")
    if not secrets.compare_digest(str(claims.get("nonce", "")), pending.nonce):
        raise OidcError("The ID token does not belong to this sign-in.")
    if not claims.get("sub"):
        raise OidcError("The ID token names no user (sub).")
    if meta.get("userinfo_endpoint") and tokens.get("access_token"):
        try:
            info = httpx.get(meta["userinfo_endpoint"], headers={"Authorization": f"Bearer {tokens['access_token']}", "Accept": "application/json"}, timeout=TIMEOUT)
            extra = info.json() if info.status_code == 200 else {}
        except (httpx.HTTPError, ValueError):
            extra = {}
        if isinstance(extra, dict) and extra.get("sub") == claims["sub"]:
            claims = {**extra, **claims}
    return Identity(sub=str(claims["sub"]), claims=claims, id_token=tokens["id_token"])


# --------------------------------------------------------------------------- accounts


def claim(claims: dict, path: str):
    """A claim by dotted path (realm_access.roles); a plain name with dots is tried first."""
    if path in claims:
        return claims[path]
    value = claims
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def mapped_role(cfg: dict, identity: Identity) -> str | None:
    raw = claim(identity.claims, cfg["role_claim"])
    values = {str(v) for v in raw} if isinstance(raw, list) else ({str(raw)} if raw not in (None, "") else set())
    return next((m["role"] for m in cfg["role_map"] if m["value"] in values), None)


def _free_username(db: Session, cfg: dict, identity: Identity) -> str:
    """The provider's username (or the email's local part); suffixed if a DNSOne account already has it."""
    raw = str(claim(identity.claims, cfg["username_claim"]) or identity.email or "").strip().lower()
    raw = raw.split("@")[0] if "@" in raw else raw
    cleaned = "".join(c if c.isalnum() or c in "._-" else "-" for c in raw).strip("-._")[:50]
    try:
        base = validation.username(cleaned)
    except validation.ValidationError:
        base = "sso-" + hashlib.sha256(identity.sub.encode()).hexdigest()[:12]
    for candidate in (base, f"{base}.sso"[:64], f"{base[:50]}.sso-{secrets.token_hex(3)}"):
        if db.scalar(select(User.id).where(User.username == candidate)) is None:
            return candidate
    raise OidcError("No free DNSOne username for this account.")


def upsert_user(db: Session, cfg: dict, identity: Identity) -> User:
    if cfg["allowed_domains"]:
        domain = identity.email.rpartition("@")[2]
        if not identity.email or not identity.email_verified or domain not in cfg["allowed_domains"]:
            raise OidcError(f"Single sign-on is open to {', '.join('@' + d for d in cfg['allowed_domains'])} accounts only.")
    role_name = mapped_role(cfg, identity)
    user = db.scalar(select(User).where(User.auth_source == "oidc", User.external_id == identity.sub))
    if user is None and identity.email and identity.email_verified:
        # Invited: an administrator created the account for single sign-on with this email.
        user = db.scalar(select(User).where(User.auth_source == "oidc", User.external_id.is_(None), func.lower(User.email) == identity.email))
        if user is not None:
            user.external_id = identity.sub
    if user is None:
        if not cfg["auto_create"]:
            raise OidcError(f"There is no DNSOne account for {identity.email or 'this user'}. Ask an administrator to invite you.")
        role_name = role_name or cfg["default_role"] or None
        if role_name is None:
            raise OidcError("Your account has no DNSOne role. Ask an administrator to give you one at the sign-in provider.")
        user = User(username=_free_username(db, cfg, identity), auth_source="oidc", external_id=identity.sub, password_hash=None,
                    role_id=0, email=identity.email[:254])
        db.add(user)
    elif not user.enabled:
        raise OidcError("This account is disabled in DNSOne. Ask an administrator.")
    if role_name:
        role = db.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            raise OidcError(f"The role mapping names a role DNSOne no longer has: {role_name}.")
        user.role_id = role.id
    name = str(identity.claims.get("name") or "").strip()
    if name:
        user.name = name[:128]
    if identity.email:
        user.email = identity.email[:254]
    user.last_login_at = utcnow()
    db.flush()
    db.refresh(user)
    return user


def logout_url(cfg: dict, id_token: str | None) -> str | None:
    """The provider's end-session URL, so signing out of DNSOne also ends the single sign-on session."""
    if not (ready(cfg) and cfg["end_session"] and id_token):
        return None
    try:
        endpoint = discovery(cfg).get("end_session_endpoint")
    except OidcError:
        return None
    if not endpoint:
        return None
    query = {"id_token_hint": id_token, "post_logout_redirect_uri": f"{cfg['public_url']}/", "client_id": cfg["client_id"]}
    return f"{endpoint}{'&' if '?' in endpoint else '?'}{urlencode(query)}"


def check(cfg: dict) -> dict:
    """Settings → Single sign-on → Test: the provider's configuration as DNSOne sees it."""
    meta = discovery(cfg, force=True)
    keys = _get_json(meta["jwks_uri"], ttl=3600, force=True).get("keys", [])
    problems = []
    if meta["issuer"] != cfg["issuer"]:
        problems.append(f"The provider calls itself {meta['issuer']}; enter exactly that as the issuer.")
    if "code" not in (meta.get("response_types_supported") or ["code"]):
        problems.append("The provider does not offer the authorization code flow.")
    if "S256" not in (meta.get("code_challenge_methods_supported") or ["S256"]):
        problems.append("The provider does not support PKCE (S256).")
    return {"issuer": meta["issuer"], "authorization_endpoint": meta["authorization_endpoint"], "token_endpoint": meta["token_endpoint"],
            "userinfo_endpoint": meta.get("userinfo_endpoint"), "end_session_endpoint": meta.get("end_session_endpoint"),
            "keys": len(keys), "problems": problems, "redirect_uri": redirect_uri(cfg)}
