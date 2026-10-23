"""Settings -> Single sign-on: Keycloak's users and realm settings, managed from DNSOne.

Keycloak stays the source of truth: everything here is read from and written to its admin API
(kcadmin). DNSOne keeps only its own view of each operator (users row, found by Keycloak's id),
and ends that operator's DNSOne sessions whenever Keycloak access is taken away (disable, delete,
sign out everywhere), so a removed operator does not keep a 12-hour session.

What is covered: users and their DNSOne role, passwords, invitations, two-factor, sessions; the
password policy, brute-force lockout, required two-factor, session lengths and "remember me";
sign-in with Google, Microsoft or another OpenID Connect provider; Active Directory / LDAP; the
sign-in event log; the email server Keycloak sends password and invitation mails with. Anything else
is in Keycloak's own admin console (<console>/auth/admin/).
"""

from __future__ import annotations

import hashlib
import re
import secrets
import smtplib
import ssl
import string
from datetime import timedelta
from email.message import EmailMessage

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import kcadmin, security, validation
from .config import Settings, get_settings
from .models import Setting, User
from .system import utcnow


def _keycloak_role(dnsone_role: str, s: Settings) -> str:
    for keycloak, dnsone in s.oidc_roles:
        if dnsone == dnsone_role:
            return keycloak
    raise validation.ValidationError("role", f"Choose one of: {', '.join(d for _, d in s.oidc_roles)}.")


def _dnsone_role(realm_roles: set[str], s: Settings) -> str | None:
    return next((dnsone for keycloak, dnsone in s.oidc_roles if keycloak in realm_roles), None)


def _linked(db: Session, kc_id: str) -> User | None:
    return db.scalar(select(User).where(User.auth_source == "oidc", User.external_id == kc_id))


def _end_dnsone_sessions(db: Session, kc_id: str) -> None:
    user = _linked(db, kc_id)
    if user is not None:
        security.end_user_sessions(db, user.id)


def random_password() -> str:
    alphabet = string.ascii_letters + string.digits
    # Letters, digits and one of each kind Keycloak's policies usually ask for.
    return "".join(secrets.choice(alphabet) for _ in range(16)) + "-" + secrets.choice(string.digits) + secrets.choice(string.ascii_uppercase)


# --------------------------------------------------------------------------- users


def _user_out(u: dict, role: str | None, credentials: list[dict], linked: User | None, me: str | None) -> dict:
    types = {c.get("type") for c in credentials}
    return {
        "id": u["id"], "username": u.get("username", ""), "email": u.get("email", ""),
        "first_name": u.get("firstName", ""), "last_name": u.get("lastName", ""),
        "name": " ".join(x for x in (u.get("firstName"), u.get("lastName")) if x),
        "enabled": bool(u.get("enabled")), "email_verified": bool(u.get("emailVerified")),
        "role": role, "two_factor": "otp" in types, "passkey": bool(types & {"webauthn", "webauthn-passwordless"}),
        "required_actions": u.get("requiredActions") or [], "federated": bool(u.get("federationLink")),
        "created": u.get("createdTimestamp"), "last_login_at": security.iso(linked.last_login_at) if linked else None,
        "self": u["id"] == me,
    }


def list_users(db: Session, q: str, page: int, size: int, me: str | None) -> dict:
    s = get_settings()
    total = int(kcadmin.get("/users/count", search=q) or 0)
    pages = max(1, -(-total // size))
    page = min(page, pages)
    users = kcadmin.get("/users", search=q, first=(page - 1) * size, max=size, briefRepresentation="false") or []
    rows = []
    for u in users:
        if u.get("username", "").startswith("service-account-"):
            continue
        realm_roles = {r["name"] for r in kcadmin.get(f"/users/{u['id']}/role-mappings/realm") or []}
        credentials = kcadmin.get(f"/users/{u['id']}/credentials") or []
        rows.append(_user_out(u, _dnsone_role(realm_roles, s), credentials, _linked(db, u["id"]), me))
    return {"rows": rows, "total": total, "page": page, "pages": pages, "size": size}


def get_user(db: Session, kc_id: str, me: str | None) -> dict:
    s = get_settings()
    u = kcadmin.get(f"/users/{kc_id}")
    realm_roles = {r["name"] for r in kcadmin.get(f"/users/{kc_id}/role-mappings/realm") or []}
    out = _user_out(u, _dnsone_role(realm_roles, s), kcadmin.get(f"/users/{kc_id}/credentials") or [], _linked(db, kc_id), me)
    out["sessions"] = [{"ip": x.get("ipAddress"), "started": x.get("start"), "last_access": x.get("lastAccess"),
                        "clients": sorted((x.get("clients") or {}).values())} for x in kcadmin.get(f"/users/{kc_id}/sessions") or []]
    return out


def _set_role(kc_id: str, role: str | None, s: Settings) -> None:
    """Gives the user exactly one of DNSOne's Keycloak roles (or none)."""
    current = kcadmin.get(f"/users/{kc_id}/role-mappings/realm") or []
    ours = {k for k, _ in s.oidc_roles}
    drop = [r for r in current if r["name"] in ours and (role is None or r["name"] != _keycloak_role(role, s))]
    if drop:
        kcadmin.call("DELETE", f"/users/{kc_id}/role-mappings/realm", json=drop)
    if role is not None and not any(r["name"] == _keycloak_role(role, s) for r in current):
        kcadmin.call("POST", f"/users/{kc_id}/role-mappings/realm", json=[kcadmin.get(f"/roles/{_keycloak_role(role, s)}")])


def _required_actions(u: dict, require_2fa: bool | None, update_password: bool = False) -> list[str]:
    actions = set(u.get("requiredActions") or [])
    if require_2fa is True:
        actions.add("CONFIGURE_TOTP")
    elif require_2fa is False:
        actions.discard("CONFIGURE_TOTP")
    if update_password:
        actions.add("UPDATE_PASSWORD")
    return sorted(actions)


def create_user(data: dict) -> tuple[str, str | None]:
    """Creates a Keycloak user with a DNSOne role. Returns (Keycloak id, temporary password or None)."""
    s = get_settings()
    username = validation.username(str(data.get("username") or ""))
    email = validation.email(str(data.get("email") or ""))
    role = str(data.get("role") or "")
    _keycloak_role(role, s)
    invite = bool(data.get("invite"))
    if invite and not email:
        raise validation.ValidationError("email", "An invitation is sent by email: enter the address.")
    password = str(data.get("password") or "")
    generated = None
    if not invite and not password:
        password = generated = random_password()
    first, last = str(data.get("first_name") or "").strip()[:255], str(data.get("last_name") or "").strip()[:255]
    rep = {"username": username, "email": email or None, "firstName": first, "lastName": last, "enabled": True,
           "emailVerified": bool(email), "requiredActions": _required_actions({}, bool(data.get("require_2fa")), update_password=invite)}
    try:
        kc_id = kcadmin.call("POST", "/users", json=rep)
    except kcadmin.KeycloakError as exc:
        if exc.status == 409:
            raise validation.ValidationError("username", "A Keycloak user with this username or email already exists.") from None
        raise
    _set_role(kc_id, role, s)
    if password:
        _set_password(kc_id, password, temporary=bool(data.get("temporary", True)))
    if invite:
        send_actions_email(kc_id, ["UPDATE_PASSWORD"])
    return kc_id, generated


def _set_password(kc_id: str, password: str, temporary: bool) -> None:
    try:
        kcadmin.call("PUT", f"/users/{kc_id}/reset-password", json={"type": "password", "value": password, "temporary": temporary})
    except kcadmin.KeycloakError as exc:
        if exc.status == 400:
            # Keycloak's password policy said no; its message names the rule.
            raise validation.ValidationError("password", exc.args[0]) from None
        raise


def set_password(kc_id: str, password: str | None, temporary: bool) -> str | None:
    """Sets the given password, or a generated one (returned, shown once)."""
    generated = None if password else random_password()
    _set_password(kc_id, password or generated, temporary)
    return generated


def send_actions_email(kc_id: str, actions: list[str]) -> None:
    try:
        kcadmin.call("PUT", f"/users/{kc_id}/execute-actions-email", json=actions, params={"lifespan": 86400})
    except kcadmin.KeycloakError as exc:
        raise validation.ValidationError("email", f"Keycloak could not send the email ({exc.args[0]}). Check Settings -> Single sign-on -> Email.") from None


def update_user(db: Session, kc_id: str, data: dict, me: str | None) -> None:
    s = get_settings()
    u = kcadmin.get(f"/users/{kc_id}")
    if kc_id == me and (data.get("enabled") is False or ("role" in data and data["role"] != "admin")):
        raise validation.ValidationError("role", "You cannot disable yourself or take away your own administrator role.")
    rep: dict = {}
    if "email" in data:
        email = validation.email(str(data.get("email") or ""))
        rep["email"] = email or None
        if email != (u.get("email") or ""):
            rep["emailVerified"] = bool(email)
    for key, field in (("first_name", "firstName"), ("last_name", "lastName")):
        if key in data:
            rep[field] = str(data[key] or "").strip()[:255]
    if "enabled" in data:
        rep["enabled"] = bool(data["enabled"])
    if "require_2fa" in data:
        rep["requiredActions"] = _required_actions(u, bool(data["require_2fa"]))
    if rep:
        try:
            kcadmin.call("PUT", f"/users/{kc_id}", json=rep)
        except kcadmin.KeycloakError as exc:
            if exc.status == 409:
                raise validation.ValidationError("email", "Another Keycloak user has this email address.") from None
            raise
    if "role" in data:
        _set_role(kc_id, data["role"] or None, s)
    if data.get("enabled") is False or ("role" in data and not data["role"]):
        sign_out_everywhere(db, kc_id)


def reset_two_factor(kc_id: str) -> int:
    """Removes the user's authenticator-app credentials (lost phone); they set one up again at sign-in."""
    removed = 0
    for credential in kcadmin.get(f"/users/{kc_id}/credentials") or []:
        if credential.get("type") == "otp":
            kcadmin.call("DELETE", f"/users/{kc_id}/credentials/{credential['id']}")
            removed += 1
    return removed


def sign_out_everywhere(db: Session, kc_id: str) -> None:
    kcadmin.call("POST", f"/users/{kc_id}/logout")
    _end_dnsone_sessions(db, kc_id)


def delete_user(db: Session, kc_id: str, me: str | None) -> None:
    if kc_id == me:
        raise validation.ValidationError("id", "You cannot delete your own account.")
    kcadmin.call("DELETE", f"/users/{kc_id}")
    user = _linked(db, kc_id)
    if user is not None:
        security.end_user_sessions(db, user.id)
        user.enabled = False


# --------------------------------------------------------------------------- security policy

_POLICY_KEYS = {"length": "length", "upperCase": "upper", "lowerCase": "lower", "digits": "digits", "specialChars": "special",
                "passwordHistory": "history", "forceExpiredPasswordChange": "expire_days"}


def _parse_policy(text: str) -> dict:
    out = {"length": 0, "upper": 0, "lower": 0, "digits": 0, "special": 0, "history": 0, "expire_days": 0, "not_username": False}
    for name, arg in re.findall(r"(\w+)\(([^)]*)\)", text or ""):
        if name == "notUsername":
            out["not_username"] = True
        elif name in _POLICY_KEYS:
            try:
                out[_POLICY_KEYS[name]] = int(arg)
            except ValueError:
                pass
    return out


def _render_policy(p: dict, existing: str) -> str:
    # Keep policies the panel does not show (e.g. hash iterations) as they are.
    keep = [f"{n}({a})" for n, a in re.findall(r"(\w+)\(([^)]*)\)", existing or "") if n not in _POLICY_KEYS and n != "notUsername"]
    parts = [f"{name}({int(p[key])})" for name, key in _POLICY_KEYS.items() if int(p.get(key) or 0) > 0]
    if p.get("not_username"):
        parts.append("notUsername(undefined)")
    return " and ".join(parts + keep)


def get_security() -> dict:
    r = kcadmin.realm()
    totp = kcadmin.get("/authentication/required-actions/CONFIGURE_TOTP") or {}
    return {
        "password": _parse_policy(r.get("passwordPolicy", "")),
        "brute_force": {"enabled": bool(r.get("bruteForceProtected")), "max_failures": int(r.get("failureFactor") or 5),
                        "lock_minutes": int(r.get("maxFailureWaitSeconds") or 900) // 60, "permanent": bool(r.get("permanentLockout"))},
        "two_factor_required": bool(totp.get("defaultAction")),
        "sessions": {"idle_minutes": int(r.get("ssoSessionIdleTimeout") or 1800) // 60, "max_hours": int(r.get("ssoSessionMaxLifespan") or 36000) // 3600},
        "remember_me": bool(r.get("rememberMe")),
        "reset_password": bool(r.get("resetPasswordAllowed")),
    }


def store_security(data: dict) -> dict:
    p = data.get("password") or {}
    for key in ("length", "upper", "lower", "digits", "special", "history", "expire_days"):
        value = int(p.get(key) or 0)
        if not 0 <= value <= (3650 if key == "expire_days" else 128):
            raise validation.ValidationError(f"password.{key}", "Out of range.")
        p[key] = value
    if p["length"] and p["length"] < 8:
        raise validation.ValidationError("password.length", "At least 8 characters (or 0 for no rule).")
    b = data.get("brute_force") or {}
    sess = data.get("sessions") or {}
    max_failures, lock_minutes = int(b.get("max_failures") or 5), int(b.get("lock_minutes") or 15)
    idle, max_hours = int(sess.get("idle_minutes") or 30), int(sess.get("max_hours") or 12)
    if not 1 <= max_failures <= 100:
        raise validation.ValidationError("brute_force.max_failures", "Between 1 and 100.")
    if not 1 <= lock_minutes <= 1440:
        raise validation.ValidationError("brute_force.lock_minutes", "Between 1 and 1440 minutes.")
    if not 5 <= idle <= 1440:
        raise validation.ValidationError("sessions.idle_minutes", "Between 5 and 1440 minutes.")
    if not 1 <= max_hours <= 720:
        raise validation.ValidationError("sessions.max_hours", "Between 1 and 720 hours.")
    current = kcadmin.realm()
    kcadmin.update_realm({
        "passwordPolicy": _render_policy(p, current.get("passwordPolicy", "")),
        "bruteForceProtected": bool(b.get("enabled", True)), "failureFactor": max_failures, "permanentLockout": bool(b.get("permanent")),
        "maxFailureWaitSeconds": lock_minutes * 60, "waitIncrementSeconds": lock_minutes * 60, "maxDeltaTimeSeconds": 43200,
        "ssoSessionIdleTimeout": idle * 60, "ssoSessionMaxLifespan": max_hours * 3600,
        "rememberMe": bool(data.get("remember_me")), "resetPasswordAllowed": bool(data.get("reset_password")),
    })
    totp = kcadmin.get("/authentication/required-actions/CONFIGURE_TOTP")
    required = bool(data.get("two_factor_required"))
    if bool(totp.get("defaultAction")) != required or not totp.get("enabled"):
        kcadmin.call("PUT", "/authentication/required-actions/CONFIGURE_TOTP", json={**totp, "enabled": True, "defaultAction": required})
    applied = 0
    if required and data.get("apply_to_existing"):
        # Everyone without an authenticator app sets one up at their next sign-in.
        first = 0
        while True:
            batch = kcadmin.get("/users", first=first, max=100, briefRepresentation="false") or []
            for u in batch:
                if u.get("username", "").startswith("service-account-") or "CONFIGURE_TOTP" in (u.get("requiredActions") or []):
                    continue
                if not any(c.get("type") == "otp" for c in kcadmin.get(f"/users/{u['id']}/credentials") or []):
                    kcadmin.call("PUT", f"/users/{u['id']}", json={"requiredActions": _required_actions(u, True)})
                    applied += 1
            if len(batch) < 100:
                break
            first += 100
    return {**get_security(), "applied": applied}


# --------------------------------------------------------------------------- sign-in providers

PROVIDERS = {"google": "Google", "microsoft": "Microsoft", "oidc": "OpenID Connect"}


def broker_redirect(alias: str, s: Settings | None = None) -> str:
    s = s or get_settings()
    return f"{s.public_url}/auth/realms/{s.keycloak_realm}/broker/{alias}/endpoint"


def list_providers() -> list[dict]:
    out = []
    for p in kcadmin.get("/identity-provider/instances") or []:
        out.append({"alias": p["alias"], "type": p.get("providerId"), "name": p.get("displayName") or PROVIDERS.get(p.get("providerId"), p["alias"]),
                    "enabled": bool(p.get("enabled")), "redirect_uri": broker_redirect(p["alias"])})
    return out


def add_provider(data: dict) -> dict:
    kind = data.get("type")
    if kind not in PROVIDERS:
        raise validation.ValidationError("type", "Choose Google, Microsoft or OpenID Connect.")
    client_id, secret = str(data.get("client_id") or "").strip(), str(data.get("client_secret") or "").strip()
    if not client_id or not secret:
        raise validation.ValidationError("client_id", "Enter the client ID and secret from the provider's developer console.")
    alias = kind if kind != "oidc" else re.sub(r"[^a-z0-9-]", "-", str(data.get("alias") or "").strip().lower())[:40]
    if not alias:
        raise validation.ValidationError("alias", "Give the provider a short name, e.g. company-sso.")
    config = {"clientId": client_id, "clientSecret": secret, "syncMode": "IMPORT", "guiOrder": "1"}
    if kind == "microsoft" and data.get("tenant"):
        config["tenantId"] = str(data["tenant"]).strip()
    if kind == "google" and data.get("hosted_domain"):
        config["hostedDomain"] = str(data["hosted_domain"]).strip()
    if kind == "oidc":
        discovery = str(data.get("discovery_url") or "").strip()
        if not discovery.startswith("https://"):
            raise validation.ValidationError("discovery_url", "Enter the provider's https://…/.well-known/openid-configuration URL.")
        try:
            imported = kcadmin.call("POST", "/identity-provider/import-config", json={"providerId": "oidc", "fromUrl": discovery})
        except kcadmin.KeycloakError as exc:
            raise validation.ValidationError("discovery_url", f"Keycloak could not read it ({exc.args[0]}).") from None
        config = {**imported, **config, "clientAuthMethod": "client_secret_post", "defaultScope": "openid email profile", "validateSignature": "true", "useJwksUrl": "true"}
    rep = {"alias": alias, "providerId": kind, "enabled": True, "displayName": str(data.get("name") or PROVIDERS[kind])[:64],
           "trustEmail": bool(data.get("trust_email", True)), "firstBrokerLoginFlowAlias": "first broker login", "config": config}
    try:
        kcadmin.call("POST", "/identity-provider/instances", json=rep)
    except kcadmin.KeycloakError as exc:
        if exc.status == 409:
            raise validation.ValidationError("alias", "A provider with this name already exists.") from None
        raise
    return {"alias": alias, "redirect_uri": broker_redirect(alias)}


def set_provider_enabled(alias: str, enabled: bool) -> None:
    rep = kcadmin.get(f"/identity-provider/instances/{alias}")
    rep["enabled"] = enabled
    kcadmin.call("PUT", f"/identity-provider/instances/{alias}", json=rep)


def delete_provider(alias: str) -> None:
    kcadmin.call("DELETE", f"/identity-provider/instances/{alias}")


# --------------------------------------------------------------------------- Active Directory / LDAP

LDAP_TYPE = "org.keycloak.storage.UserStorageProvider"


def _ldap_config(data: dict) -> dict:
    url = str(data.get("url") or "").strip()
    if not re.match(r"^ldaps?://[^\s]+$", url):
        raise validation.ValidationError("url", "Enter ldaps://dc1.example.local:636 (or ldap://…).")
    bind_dn, users_dn = str(data.get("bind_dn") or "").strip(), str(data.get("users_dn") or "").strip()
    if not users_dn:
        raise validation.ValidationError("users_dn", "Enter where the users are, e.g. OU=Staff,DC=example,DC=local.")
    ad = data.get("vendor", "ad") == "ad"
    config = {
        "vendor": ["ad" if ad else "other"], "connectionUrl": [url], "bindDn": [bind_dn], "bindCredential": [str(data.get("bind_password") or "")],
        "usersDn": [users_dn], "authType": ["simple" if bind_dn else "none"], "editMode": ["READ_ONLY"], "searchScope": ["2"],
        "usernameLDAPAttribute": ["sAMAccountName" if ad else "uid"], "rdnLDAPAttribute": ["cn" if ad else "uid"],
        "uuidLDAPAttribute": ["objectGUID" if ad else "entryUUID"],
        "userObjectClasses": ["person, organizationalPerson, user" if ad else "inetOrgPerson, organizationalPerson"],
        "customUserSearchFilter": [str(data.get("filter") or "").strip()], "enabled": ["true"], "importEnabled": ["true"],
        "syncRegistrations": ["false"], "pagination": ["true"], "trustEmail": ["true"], "useTruststoreSpi": ["always"],
        "fullSyncPeriod": ["86400"], "changedSyncPeriod": ["3600"], "batchSizeForSync": ["1000"], "connectionTimeout": ["5000"],
    }
    return config


def list_ldap() -> list[dict]:
    out = []
    for c in kcadmin.get("/components", type=LDAP_TYPE) or []:
        cfg = c.get("config") or {}
        first = lambda k: (cfg.get(k) or [""])[0]  # noqa: E731
        out.append({"id": c["id"], "name": c.get("name"), "url": first("connectionUrl"), "vendor": first("vendor"),
                    "users_dn": first("usersDn"), "bind_dn": first("bindDn"), "enabled": first("enabled") == "true"})
    return out


def test_ldap(data: dict) -> None:
    config = _ldap_config(data)
    body = {"action": "testAuthentication" if config["bindDn"][0] else "testConnection", "connectionUrl": config["connectionUrl"][0],
            "bindDn": config["bindDn"][0], "bindCredential": config["bindCredential"][0], "useTruststoreSpi": "always", "connectionTimeout": "5000"}
    try:
        kcadmin.call("POST", "/testLDAPConnection", json=body)
    except kcadmin.KeycloakError as exc:
        raise validation.ValidationError("url", f"Keycloak could not connect or sign in to the directory ({exc.args[0]}).") from None


def add_ldap(data: dict) -> dict:
    config = _ldap_config(data)
    name = str(data.get("name") or "Active Directory").strip()[:64]
    realm_id = kcadmin.realm()["id"]
    cid = kcadmin.call("POST", "/components", json={"name": name, "providerId": "ldap", "providerType": LDAP_TYPE, "parentId": realm_id, "config": config})
    return {"id": cid, "sync": sync_ldap(cid)}


def sync_ldap(component_id: str) -> dict:
    result = kcadmin.call("POST", f"/user-storage/{component_id}/sync", params={"action": "triggerFullSync"}) or {}
    return {k: result.get(k) for k in ("added", "updated", "removed", "failed", "status")}


def delete_ldap(component_id: str) -> None:
    kcadmin.call("DELETE", f"/components/{component_id}")


# --------------------------------------------------------------------------- events and email


def events(kind: str, user: str, page: int, size: int) -> dict:
    rows = kcadmin.get("/events", type=kind or None, user=user or None, first=(page - 1) * size, max=size + 1) or []
    out = [{"time": e.get("time"), "type": e.get("type"), "username": (e.get("details") or {}).get("username") or e.get("userId"),
            "ip": e.get("ipAddress"), "client": e.get("clientId"), "error": e.get("error")} for e in rows[:size]]
    return {"rows": out, "page": page, "more": len(rows) > size}


def get_email() -> dict:
    smtp = kcadmin.realm().get("smtpServer") or {}
    return {"host": smtp.get("host", ""), "port": int(smtp.get("port") or 587), "from": smtp.get("from", ""),
            "from_name": smtp.get("fromDisplayName", ""), "security": "tls" if smtp.get("ssl") == "true" else "starttls" if smtp.get("starttls") == "true" else "none",
            "user": smtp.get("user", ""), "password_set": bool(smtp.get("password"))}


def store_email(data: dict) -> dict:
    host = str(data.get("host") or "").strip()[:253]
    sender = validation.email(str(data.get("from") or ""))
    port = int(data.get("port") or 587)
    if host and not sender:
        raise validation.ValidationError("from", "Enter the sender address, e.g. no-reply@isp.example.")
    if not 1 <= port <= 65535:
        raise validation.ValidationError("port", "Between 1 and 65535.")
    sec = data.get("security") if data.get("security") in ("tls", "starttls", "none") else "starttls"
    user = str(data.get("user") or "").strip()
    smtp = {"host": host, "port": str(port), "from": sender, "fromDisplayName": str(data.get("from_name") or "")[:64],
            "ssl": str(sec == "tls").lower(), "starttls": str(sec == "starttls").lower(), "auth": str(bool(user)).lower(), "user": user}
    # Keycloak keeps the stored password when it gets its mask back.
    smtp["password"] = str(data.get("password") or "") or "**********"
    kcadmin.update_realm({"smtpServer": smtp if host else {}})
    return get_email()


def test_email(data: dict, to: str) -> None:
    """Sends a test mail from DNSOne with the settings in the form (Keycloak would send it to the caller's own address)."""
    to = validation.email(to)
    if not to:
        raise validation.ValidationError("to", "Enter an address to send the test to.")
    host, port = str(data.get("host") or ""), int(data.get("port") or 587)
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = "DNSOne: single sign-on email test", str(data.get("from") or ""), to
    msg.set_content("Keycloak will send password and invitation emails with these settings.")
    context = ssl.create_default_context()
    try:
        server = smtplib.SMTP_SSL(host, port, timeout=10, context=context) if data.get("security") == "tls" else smtplib.SMTP(host, port, timeout=10)
        with server:
            if data.get("security") == "starttls":
                server.starttls(context=context)
            if data.get("user"):
                if not data.get("password"):
                    raise validation.ValidationError("password", "Enter the password to test (the stored one is not readable).")
                server.login(str(data["user"]), str(data["password"]))
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise validation.ValidationError("host", f"Sending failed: {exc}") from None


# --------------------------------------------------------------------------- moving local accounts


def local_accounts(db: Session) -> list[User]:
    return list(db.scalars(select(User).where(User.auth_source == "local").order_by(User.username)))


def migrate_local_users(db: Session) -> list[dict]:
    """Moves every local account to Keycloak (same username, email, name and role) and links it.

    Returns, per account, the temporary password to hand over (shown once), or "linked" when a Keycloak
    user of that name already existed. The DNSOne account keeps its id, app passwords and history.
    """
    s = get_settings()
    out = []
    for user in local_accounts(db):
        existing = kcadmin.get("/users", username=user.username, exact="true") or []
        password = None
        if existing:
            kc_id = existing[0]["id"]
        else:
            first, _, last = (user.name or "").partition(" ")
            password = random_password()
            kc_id = kcadmin.call("POST", "/users", json={
                "username": user.username, "email": user.email or None, "firstName": first, "lastName": last,
                "enabled": user.enabled, "emailVerified": bool(user.email), "requiredActions": ["UPDATE_PASSWORD"]})
            _set_password(kc_id, password, temporary=True)
        _set_role(kc_id, user.role.name if user.role.name in {d for _, d in s.oidc_roles} else "viewer", s)
        user.auth_source, user.external_id, user.password_hash = "oidc", kc_id, None
        user.totp_enabled, user.totp_secret, user.recovery_codes = False, None, None
        out.append({"username": user.username, "temporary_password": password, "linked": not password})
    db.flush()
    return out


# --------------------------------------------------------------------------- emergency access

EMERGENCY_KEY = "auth.emergency"
EMERGENCY_MINUTES = 10


def create_emergency_link(db: Session, username: str) -> str:
    """A one-time sign-in link for when Keycloak is down (dnsone-ctl emergency-login)."""
    s = get_settings()
    user = db.scalar(select(User).where(User.username == username.strip().lower()))
    if user is None or not user.enabled:
        raise validation.ValidationError("username", f"No enabled DNSOne account named {username}.")
    token = secrets.token_urlsafe(32)
    value = {"hash": hashlib.sha256(token.encode()).hexdigest(), "user_id": user.id,
             "expires": (utcnow() + timedelta(minutes=EMERGENCY_MINUTES)).isoformat(timespec="seconds")}
    row = db.get(Setting, EMERGENCY_KEY)
    if row is None:
        db.add(Setting(name=EMERGENCY_KEY, value=value))
    else:
        row.value = value
    base = s.public_url or "https://<console>"
    return f"{base}/api/auth/emergency?token={token}"


def use_emergency_link(db: Session, token: str) -> User | None:
    row = db.get(Setting, EMERGENCY_KEY)
    if row is None or not token:
        return None
    value = dict(row.value)
    db.delete(row)  # single use, whatever the outcome
    if not secrets.compare_digest(value.get("hash", ""), hashlib.sha256(token.encode()).hexdigest()):
        return None
    if value.get("expires", "") < utcnow().isoformat(timespec="seconds"):
        return None
    user = db.get(User, value.get("user_id"))
    return user if user is not None and user.enabled else None
