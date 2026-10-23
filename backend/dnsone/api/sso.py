"""Settings -> Single sign-on: Keycloak users and realm settings (see ssoadmin)."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, kcadmin, oidc, ssoadmin, validation
from ..config import get_settings
from ..db import get_db
from .deps import Actor, ApiError, field_error, require

router = APIRouter(prefix="/api/sso", tags=["single sign-on"])


def _keycloak(exc: kcadmin.KeycloakError) -> ApiError:
    if exc.status == 404:
        return ApiError(404, "Not found in Keycloak.")
    return ApiError(502 if exc.status in (0, 500, 502, 503) else 422, f"Keycloak: {exc.args[0]}")


def _me(actor: Actor) -> str | None:
    return actor.user.external_id if actor.user.auth_source == "oidc" else None


def _run(fn, *args):
    try:
        return fn(*args)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    except kcadmin.KeycloakError as exc:
        raise _keycloak(exc) from None


class UserIn(BaseModel):
    username: str = Field(max_length=64)
    email: str = Field(default="", max_length=254)
    first_name: str = Field(default="", max_length=255)
    last_name: str = Field(default="", max_length=255)
    role: str = Field(max_length=32)
    # Empty and no invite: a password is generated and shown once.
    password: str = Field(default="", max_length=256)
    temporary: bool = True
    invite: bool = False
    require_2fa: bool = False


class UserPatch(BaseModel):
    email: str | None = Field(default=None, max_length=254)
    first_name: str | None = Field(default=None, max_length=255)
    last_name: str | None = Field(default=None, max_length=255)
    role: str | None = Field(default=None, max_length=32)
    enabled: bool | None = None
    require_2fa: bool | None = None


class PasswordIn(BaseModel):
    # Empty: generated (shown once). email: Keycloak mails a link to set one instead.
    password: str = Field(default="", max_length=256)
    temporary: bool = True
    email: bool = False


class ProviderIn(BaseModel):
    type: Literal["google", "microsoft", "oidc"]
    client_id: str = Field(max_length=512)
    client_secret: str = Field(max_length=1024)
    name: str = Field(default="", max_length=64)
    alias: str = Field(default="", max_length=40)
    tenant: str = Field(default="", max_length=128)
    hosted_domain: str = Field(default="", max_length=253)
    discovery_url: str = Field(default="", max_length=2048)
    trust_email: bool = True


class LdapIn(BaseModel):
    name: str = Field(default="Active Directory", max_length=64)
    vendor: Literal["ad", "other"] = "ad"
    url: str = Field(max_length=512)
    bind_dn: str = Field(default="", max_length=512)
    bind_password: str = Field(default="", max_length=512)
    users_dn: str = Field(max_length=512)
    filter: str = Field(default="", max_length=1024)


class EmailIn(BaseModel):
    host: str = Field(default="", max_length=253)
    port: int = 587
    security: Literal["tls", "starttls", "none"] = "starttls"
    user: str = Field(default="", max_length=254)
    password: str = Field(default="", max_length=512)
    from_: str = Field(default="", max_length=254, alias="from")
    from_name: str = Field(default="", max_length=64)
    test_to: str = Field(default="", max_length=254)

    model_config = {"populate_by_name": True}


# --------------------------------------------------------------------------- overview


@router.get("")
def overview(actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    s = get_settings()
    return {
        "enabled": oidc.enabled(s), "admin_api": kcadmin.configured(s), "local_login": s.local_login,
        "realm": s.keycloak_realm, "issuer": s.oidc_issuer,
        "admin_console": f"{s.public_url}/auth/admin/{s.keycloak_realm}/console/" if s.public_url else "",
        "account_console": f"{s.public_url}/auth/realms/{s.keycloak_realm}/account/" if s.public_url else "",
        "roles": [{"keycloak": k, "dnsone": d} for k, d in s.oidc_roles],
        "local_accounts": [u.username for u in ssoadmin.local_accounts(db)],
    }


# --------------------------------------------------------------------------- users


@router.get("/users")
def users(q: str = Query("", max_length=128), page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
          actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    return _run(ssoadmin.list_users, db, q.strip(), page, size, _me(actor))


@router.get("/users/{kc_id}")
def user(kc_id: str, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    return _run(ssoadmin.get_user, db, kc_id, _me(actor))


@router.post("/users", status_code=201)
def create_user(body: UserIn, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    kc_id, generated = _run(ssoadmin.create_user, body.model_dump())
    audit.record(db, actor.name, "sso.user_created", "sso_user", kc_id, {"username": body.username, "role": body.role,
                 "invite": body.invite, "require_2fa": body.require_2fa}, actor.ip)
    db.commit()
    return {"id": kc_id, "temporary_password": generated}


@router.patch("/users/{kc_id}")
def update_user(kc_id: str, body: UserPatch, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    changes = body.model_dump(exclude_unset=True)
    _run(ssoadmin.update_user, db, kc_id, changes, _me(actor))
    audit.record(db, actor.name, "sso.user_updated", "sso_user", kc_id, {"changes": changes}, actor.ip)
    db.commit()
    return _run(ssoadmin.get_user, db, kc_id, _me(actor))


@router.post("/users/{kc_id}/password")
def user_password(kc_id: str, body: PasswordIn, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    if body.email:
        _run(ssoadmin.send_actions_email, kc_id, ["UPDATE_PASSWORD"])
        generated = None
    else:
        generated = _run(ssoadmin.set_password, kc_id, body.password or None, body.temporary)
    audit.record(db, actor.name, "sso.password_reset", "sso_user", kc_id, {"by_email": body.email, "temporary": body.temporary}, actor.ip)
    db.commit()
    return {"temporary_password": generated}


@router.delete("/users/{kc_id}/two-factor")
def user_reset_two_factor(kc_id: str, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    removed = _run(ssoadmin.reset_two_factor, kc_id)
    audit.record(db, actor.name, "sso.two_factor_reset", "sso_user", kc_id, {"removed": removed}, actor.ip)
    db.commit()
    return {"removed": removed}


@router.post("/users/{kc_id}/sign-out")
def user_sign_out(kc_id: str, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    _run(ssoadmin.sign_out_everywhere, db, kc_id)
    audit.record(db, actor.name, "sso.user_signed_out", "sso_user", kc_id, None, actor.ip)
    db.commit()
    return {"ok": True}


@router.delete("/users/{kc_id}")
def delete_user(kc_id: str, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    username = _run(ssoadmin.get_user, db, kc_id, _me(actor))["username"]
    _run(ssoadmin.delete_user, db, kc_id, _me(actor))
    audit.record(db, actor.name, "sso.user_deleted", "sso_user", kc_id, {"username": username}, actor.ip)
    db.commit()
    return {"ok": True}


@router.post("/migrate-local-users")
def migrate_local_users(actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    moved = _run(ssoadmin.migrate_local_users, db)
    audit.record(db, actor.name, "sso.local_users_migrated", "sso_user", "", {"usernames": [m["username"] for m in moved]}, actor.ip)
    db.commit()
    return {"moved": moved}


# --------------------------------------------------------------------------- realm settings


@router.get("/security")
def get_security(actor: Actor = Depends(require("system.manage"))) -> dict:
    return _run(ssoadmin.get_security)


@router.put("/security")
def put_security(body: dict, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    before = _run(ssoadmin.get_security)
    after = _run(ssoadmin.store_security, body)
    audit.record(db, actor.name, "sso.security_updated", "settings", "sso.security", {"from": before, "to": {k: v for k, v in after.items() if k != "applied"}}, actor.ip)
    db.commit()
    return after


@router.get("/providers")
def providers(actor: Actor = Depends(require("system.manage"))) -> dict:
    return {"providers": _run(ssoadmin.list_providers), "redirect_example": ssoadmin.broker_redirect("<alias>")}


@router.post("/providers", status_code=201)
def add_provider(body: ProviderIn, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    out = _run(ssoadmin.add_provider, body.model_dump())
    audit.record(db, actor.name, "sso.provider_added", "settings", out["alias"], {"type": body.type}, actor.ip)
    db.commit()
    return out


@router.patch("/providers/{alias}")
def toggle_provider(alias: str, enabled: bool = Query(...), actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    _run(ssoadmin.set_provider_enabled, alias, enabled)
    audit.record(db, actor.name, "sso.provider_updated", "settings", alias, {"enabled": enabled}, actor.ip)
    db.commit()
    return {"ok": True}


@router.delete("/providers/{alias}")
def delete_provider(alias: str, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    _run(ssoadmin.delete_provider, alias)
    audit.record(db, actor.name, "sso.provider_deleted", "settings", alias, None, actor.ip)
    db.commit()
    return {"ok": True}


@router.get("/ldap")
def ldap(actor: Actor = Depends(require("system.manage"))) -> dict:
    return {"directories": _run(ssoadmin.list_ldap)}


@router.post("/ldap/test")
def ldap_test(body: LdapIn, actor: Actor = Depends(require("system.manage"))) -> dict:
    _run(ssoadmin.test_ldap, body.model_dump())
    return {"ok": True}


@router.post("/ldap", status_code=201)
def ldap_add(body: LdapIn, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    _run(ssoadmin.test_ldap, body.model_dump())
    out = _run(ssoadmin.add_ldap, body.model_dump())
    audit.record(db, actor.name, "sso.directory_added", "settings", out["id"], {"url": body.url, "users_dn": body.users_dn}, actor.ip)
    db.commit()
    return out


@router.post("/ldap/{component_id}/sync")
def ldap_sync(component_id: str, actor: Actor = Depends(require("system.manage"))) -> dict:
    return _run(ssoadmin.sync_ldap, component_id)


@router.delete("/ldap/{component_id}")
def ldap_delete(component_id: str, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    _run(ssoadmin.delete_ldap, component_id)
    audit.record(db, actor.name, "sso.directory_deleted", "settings", component_id, None, actor.ip)
    db.commit()
    return {"ok": True}


@router.get("/events")
def events(type: str = Query("", max_length=64), user: str = Query("", max_length=64), page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=200),
           actor: Actor = Depends(require("system.manage"))) -> dict:
    return _run(ssoadmin.events, type, user, page, size)


@router.get("/email")
def get_email(actor: Actor = Depends(require("system.manage"))) -> dict:
    return _run(ssoadmin.get_email)


@router.put("/email")
def put_email(body: EmailIn, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    data = body.model_dump(by_alias=True)
    if body.test_to:
        _run(ssoadmin.test_email, data, body.test_to)
    out = _run(ssoadmin.store_email, data)
    audit.record(db, actor.name, "sso.email_updated", "settings", "sso.email", {"host": body.host, "from": body.from_, "user": body.user}, actor.ip)
    db.commit()
    return out
