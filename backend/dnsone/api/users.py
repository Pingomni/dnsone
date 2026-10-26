"""Operators, customers and roles.

Administrators (users.manage) manage every account and role. Resellers (users.customers) manage
only the customer accounts they created (users.parent_id), may give them only customer roles (zone
scope 'assigned', zone permissions only), and only zones they hold themselves. Roles with zone scope
'assigned' see and change only the zones in user_zones (and those they create).
"""

from __future__ import annotations

import re
from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, insert, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, security, validation
from ..edition import pro

quota = pro("quota")
# The quota fields of an account (used only where the licence has quotas).
QUOTA_FIELDS = quota.FIELDS
from ..db import get_db
from ..models import ApiToken, Role, User, Zone, user_zones
from ..security import iso
from ..system import utcnow
from .auth import token_out
from .deps import Actor, ApiError, Paging, current_actor, field_error, like, not_found, quota_error, require

router = APIRouter(prefix="/api", tags=["users"])

PERMISSIONS = {
    "dashboard.view": "See the dashboard and statistics",
    "zones.view": "See zones and records",
    "zones.manage": "Change zones and records",
    "zones.create": "Create and delete zones",
    "templates.manage": "Manage zone templates",
    "rpz.view": "See blocklists and RPZ rules",
    "rpz.manage": "Change blocklists, RPZ rules and the block policy",
    "legal.view": "See the court-ordered blocking list",
    "legal.manage": "Add and lift court-ordered blocks",
    "queries.view": "See the query log and top lists (who asked for what)",
    "audit.view": "Read the audit log",
    "users.customers": "Create and manage own customer accounts (resellers)",
    "protection.view": "See attacks dnsdist is blocking, and the blocks",
    "protection.manage": "Block clients and domains, and change the attack thresholds",
    "firewall.manage": "Change and apply the server's firewall",
    "users.manage": "Manage every operator and role",
    "system.manage": "Open Settings and see system details",
}
# The Pro features' permissions (resellers come with quotas): offered only where the licence has the feature.
PRO_PERMISSIONS = {"legal.view": "legal", "legal.manage": "legal", "protection.view": "protection",
                   "protection.manage": "protection", "firewall.manage": "firewall", "users.customers": "quota"}


def offered_permissions() -> dict[str, str]:
    return {k: v for k, v in PERMISSIONS.items() if k not in PRO_PERMISSIONS or pro(PRO_PERMISSIONS[k])}
# What a role limited to its own zones may hold; everything else is server-wide.
ZONE_PERMISSIONS = ("zones.view", "zones.manage", "zones.create", "users.customers")
# What a reseller may give its customers.
CUSTOMER_PERMISSIONS = ("zones.view", "zones.manage", "zones.create")
ROLE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")


class UserIn(BaseModel):
    username: str = Field(max_length=64)
    name: str = Field(default="", max_length=128)
    email: str = Field(default="", max_length=254)
    role_id: int
    # local: signs in with a password. oidc: through single sign-on, matched by email at the first sign-in.
    auth_source: Literal["local", "oidc"] = "local"
    password: str = Field(default="", max_length=256)
    enabled: bool = True
    # Administrators only: the reseller this customer belongs to.
    parent_id: int | None = None
    zone_ids: list[int] | None = None
    # Quotas (accounts limited to their own zones); None: no limit.
    max_zones: int | None = None
    max_records: int | None = None
    api_rate: int | None = None


class UserPatch(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=254)
    role_id: int | None = None
    password: str | None = Field(default=None, max_length=256)
    enabled: bool | None = None
    # Lost phone: turns two-factor sign-in off so the user can sign in and enrol again.
    reset_two_factor: bool = False
    parent_id: int | None = None
    clear_parent: bool = False
    # Quotas: a field sent as null removes the limit; a field left out keeps it.
    max_zones: int | None = None
    max_records: int | None = None
    api_rate: int | None = None


class ZonesIn(BaseModel):
    zone_ids: list[int] = Field(max_length=100000)


class RoleIn(BaseModel):
    name: str = Field(max_length=32)
    description: str = Field(default="", max_length=255)
    permissions: list[str] = Field(max_length=50)
    zone_scope: Literal["all", "assigned"] = "all"


class RolePatch(BaseModel):
    description: str | None = Field(default=None, max_length=255)
    permissions: list[str] | None = Field(default=None, max_length=50)
    zone_scope: Literal["all", "assigned"] | None = None


def user_out(u: User, me: int, zones: int | None = None) -> dict:
    return {"id": u.id, "username": u.username, "name": u.name, "email": u.email, "role": u.role.name, "role_id": u.role_id,
            "zone_scope": u.role.zone_scope, "zones": zones, "parent_id": u.parent_id,
            "enabled": u.enabled, "auth_source": u.auth_source, "sso_linked": bool(u.external_id), "last_login_at": iso(u.last_login_at),
            "locked": bool(u.locked_until and u.locked_until > utcnow()), "self": u.id == me, "created_at": iso(u.created_at),
            "two_factor_enabled": u.totp_enabled, "max_zones": u.max_zones, "max_records": u.max_records, "api_rate": u.api_rate}


def role_out(r: Role, users: int = 0) -> dict:
    return {"id": r.id, "name": r.name, "description": r.description, "permissions": r.permissions, "zone_scope": r.zone_scope,
            "built_in": r.built_in, "users": users}


# --------------------------------------------------------------------------- who manages whom


def manager(actor: Actor = Depends(current_actor)) -> Actor:
    """Administrators, or resellers for their own customers."""
    if not (actor.can("users.manage") or actor.can("users.customers")):
        raise ApiError(403, "Your role does not allow this.")
    return actor


def _reseller(actor: Actor) -> bool:
    return not actor.can("users.manage")


def _customer_role(r: Role, actor: Actor) -> bool:
    perms = set(r.permissions or [])
    return r.zone_scope == "assigned" and perms <= set(CUSTOMER_PERMISSIONS) and perms <= set(actor.permissions)


def _role(db: Session, actor: Actor, role_id: int) -> Role:
    role = db.get(Role, role_id)
    if role is None or (_reseller(actor) and not _customer_role(role, actor)):
        raise ApiError(422, "Choose a role.", {"role_id": "Choose a role."})
    return role


def _target(db: Session, actor: Actor, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None or (_reseller(actor) and user.parent_id != actor.user.id):
        raise not_found("User")
    return user


def _admins_left(db: Session, excluding: int) -> int:
    return db.scalar(
        select(func.count()).select_from(User).join(Role).where(
            User.enabled.is_(True), User.id != excluding, func.json_contains(Role.permissions, '"users.manage"') == 1
        )
    ) or 0


def _parent(db: Session, parent_id: int | None) -> int | None:
    if parent_id is None:
        return None
    parent = db.get(User, parent_id)
    if parent is None or "users.customers" not in (parent.role.permissions or []):
        raise ApiError(422, "Choose a reseller.", {"parent_id": "This user is not a reseller."})
    return parent.id


def _quotas(actor: Actor, values: dict) -> dict:
    """The quota fields of a form, checked: a reseller's customers stay within its own limits."""
    if not quota:
        return {}
    if not quota.writable and any(v is not None for v in values.values()):
        raise ApiError(402, "Your DNSOne Pro licence has expired: renew it to change quotas (Settings → License).")
    try:
        return quota.clean(values, actor.user if _reseller(actor) else None)
    except quota.QuotaExceeded as exc:
        raise quota_error(exc) from None


def _zone_count(db: Session, user_id: int) -> int:
    return db.scalar(select(func.count()).select_from(user_zones).where(user_zones.c.user_id == user_id)) or 0


def _set_zones(db: Session, actor: Actor, user: User, zone_ids: list[int]) -> tuple[list[str], list[str]]:
    """Replaces the user's zones; a reseller can only give zones it holds. Returns (added, removed) names."""
    wanted = set(zone_ids)
    allowed = actor.zone_ids(db)
    if allowed is not None and not wanted <= allowed:
        raise ApiError(422, "You can only give customers zones you manage.", {"zone_ids": "One of the zones is not yours."})
    found = dict(db.execute(select(Zone.id, Zone.name).where(Zone.id.in_(wanted))).all()) if wanted else {}
    if len(found) != len(wanted):
        raise ApiError(422, "One of the zones no longer exists.", {"zone_ids": "Choose the zones again."})
    current = set(db.scalars(select(user_zones.c.zone_id).where(user_zones.c.user_id == user.id)))
    add, remove = wanted - current, current - wanted
    if user.max_zones is not None and user.role.zone_scope == "assigned" and len(wanted) > user.max_zones and add:
        raise ApiError(422, f"{user.username} may hold at most {user.max_zones} zone(s).", {"zone_ids": f"At most {user.max_zones} zone(s)."})
    if remove:
        db.execute(delete(user_zones).where(user_zones.c.user_id == user.id, user_zones.c.zone_id.in_(remove)))
    if add:
        db.execute(insert(user_zones), [{"user_id": user.id, "zone_id": z} for z in add])
    names = dict(db.execute(select(Zone.id, Zone.name).where(Zone.id.in_(remove))).all()) if remove else {}
    return sorted(found[z] for z in add), sorted(names.get(z, str(z)) for z in remove)


# --------------------------------------------------------------------------- roles


@router.get("/roles")
def roles(actor: Actor = Depends(manager), db: Session = Depends(get_db)) -> dict:
    rows = db.scalars(select(Role).order_by(Role.id)).all()
    if _reseller(actor):
        rows = [r for r in rows if _customer_role(r, actor)]
    counts = dict(db.execute(select(User.role_id, func.count()).group_by(User.role_id)).all())
    return {
        "roles": [role_out(r, counts.get(r.id, 0)) for r in rows],
        "permissions": offered_permissions() if not _reseller(actor) else {k: v for k, v in PERMISSIONS.items() if k in CUSTOMER_PERMISSIONS},
        "zone_permissions": list(ZONE_PERMISSIONS),
    }


def _permissions(values: list[str], scope: str) -> list[str]:
    perms = sorted(set(values), key=list(PERMISSIONS).index) if set(values) <= set(PERMISSIONS) else None
    if perms is None:
        unknown = ", ".join(sorted(set(values) - set(PERMISSIONS)))
        raise validation.ValidationError("permissions", f"Unknown permission: {unknown}.")
    if scope == "assigned" and not set(perms) <= set(ZONE_PERMISSIONS):
        wide = ", ".join(p for p in perms if p not in ZONE_PERMISSIONS)
        raise validation.ValidationError("permissions", f"A role limited to its own zones can only hold zone permissions; remove {wide}.")
    if ("zones.manage" in perms or "zones.create" in perms) and "zones.view" not in perms:
        perms.insert(0, "zones.view")
    return perms


@router.post("/roles", status_code=201)
def create_role(body: RoleIn, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    name = body.name.strip().lower()
    try:
        if not ROLE_NAME.match(name):
            raise validation.ValidationError("name", "2–32 characters: lower-case letters, digits, '.', '_' and '-'.")
        perms = _permissions(body.permissions, body.zone_scope)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    role = Role(name=name, description=body.description.strip(), permissions=perms, zone_scope=body.zone_scope, built_in=False)
    db.add(role)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "A role with this name already exists.", {"name": "This name is taken."}) from None
    audit.record(db, actor.name, "role.created", "role", role.id, {"name": name, "permissions": perms, "zone_scope": body.zone_scope}, actor.ip)
    db.commit()
    return role_out(role)


@router.patch("/roles/{role_id}")
def update_role(role_id: int, body: RolePatch, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    role = db.get(Role, role_id)
    if role is None:
        raise not_found("Role")
    if role.built_in and (body.permissions is not None or body.zone_scope is not None):
        raise ApiError(422, "Built-in roles keep their permissions. Create a new role for different access.")
    before = role_out(role)
    scope = body.zone_scope or role.zone_scope
    try:
        perms = _permissions(body.permissions if body.permissions is not None else list(role.permissions), scope)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    role.permissions, role.zone_scope = perms, scope
    if body.description is not None:
        role.description = body.description.strip()
    db.flush()
    if "users.manage" not in perms and not _admins_left(db, 0):
        db.rollback()
        raise ApiError(422, "No enabled administrator would be left.", {"permissions": "Keep users.manage: this role holds the last administrators."})
    after = role_out(role)
    audit.record(db, actor.name, "role.updated", "role", role.id, {"name": role.name, "changes": {k: {"from": before[k], "to": after[k]}
                 for k in ("description", "permissions", "zone_scope") if before[k] != after[k]}}, actor.ip)
    db.commit()
    return after


@router.delete("/roles/{role_id}")
def delete_role(role_id: int, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    role = db.get(Role, role_id)
    if role is None:
        raise not_found("Role")
    if role.built_in:
        raise ApiError(422, "Built-in roles cannot be deleted.")
    if db.scalar(select(func.count()).select_from(User).where(User.role_id == role.id)):
        raise ApiError(422, "Users still have this role; give them another one first.")
    audit.record(db, actor.name, "role.deleted", "role", role.id, {"name": role.name}, actor.ip)
    db.delete(role)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- users


@router.get("/users")
def list_users(
    q: str = Query("", max_length=64),
    status: Literal["", "enabled", "disabled"] = "",
    role_id: int | None = Query(None),
    parent_id: int | None = Query(None),
    paging: Paging = Depends(),
    actor: Actor = Depends(manager),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(User)
    base = select(func.count()).select_from(User)
    if _reseller(actor):
        stmt = stmt.where(User.parent_id == actor.user.id)
        base = base.where(User.parent_id == actor.user.id)
    elif parent_id is not None:
        stmt = stmt.where(User.parent_id == parent_id)
    if q:
        stmt = stmt.where(or_(User.username.like(like(q.strip())), User.name.like(like(q.strip())), User.email.like(like(q.strip()))))
    if status:
        stmt = stmt.where(User.enabled.is_(status == "enabled"))
    if role_id is not None:
        stmt = stmt.where(User.role_id == role_id)
    counts = dict(db.execute(select(user_zones.c.user_id, func.count()).group_by(user_zones.c.user_id)).all())
    result = paging.apply(db, stmt.order_by(User.username), lambda u: user_out(u, actor.user.id, counts.get(u.id, 0)))
    result["summary"] = {
        "enabled": db.scalar(base.where(User.enabled.is_(True))) or 0,
        "total": db.scalar(base) or 0,
    }
    if not _reseller(actor):
        result["resellers"] = [{"id": u.id, "username": u.username} for u in db.scalars(
            select(User).join(Role).where(func.json_contains(Role.permissions, '"users.customers"') == 1).order_by(User.username))]
    return result


@router.post("/users", status_code=201)
def create_user(body: UserIn, actor: Actor = Depends(manager), db: Session = Depends(get_db)) -> dict:
    try:
        username = validation.username(body.username)
        email = validation.email(body.email)
        if body.auth_source == "local":
            password_hash = security.hash_password(validation.password(body.password))
        else:
            if not email:
                raise validation.ValidationError("email", "Single sign-on accounts are matched by email at the first sign-in: enter it.")
            password_hash = None
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    role = _role(db, actor, body.role_id)
    parent = actor.user.id if _reseller(actor) else _parent(db, body.parent_id)
    limits = _quotas(actor, {f: getattr(body, f) for f in QUOTA_FIELDS} if not _reseller(actor) else
                     {f: getattr(body, f) if getattr(body, f) is not None else getattr(actor.user, f) for f in QUOTA_FIELDS})
    user = User(username=username, name=body.name.strip(), email=email, role_id=role.id, enabled=body.enabled,
                password_hash=password_hash, auth_source=body.auth_source, parent_id=parent, **limits)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "This username is taken.", {"username": "This username is taken."}) from None
    added: list[str] = []
    if body.zone_ids:
        added, _ = _set_zones(db, actor, user, body.zone_ids)
    audit.record(db, actor.name, "user.created", "user", user.id, {"username": username, "role": role.name, "enabled": body.enabled,
                 "auth_source": body.auth_source, "parent_id": parent, "zones": added, **{k: v for k, v in limits.items() if v is not None}}, actor.ip)
    db.commit()
    db.refresh(user)
    return user_out(user, actor.user.id, len(added))


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatch, actor: Actor = Depends(manager), db: Session = Depends(get_db)) -> dict:
    user = _target(db, actor, user_id)
    changes: dict = {}
    try:
        if body.name is not None:
            user.name = body.name.strip()
            changes["name"] = user.name
        if body.email is not None:
            user.email = validation.email(body.email)
            changes["email"] = user.email
        if body.password:
            if user.auth_source != "local":
                raise validation.ValidationError("password", "This user signs in with single sign-on.")
            user.password_hash = security.hash_password(validation.password(body.password))
            user.locked_until, user.failed_logins = None, 0
            security.end_user_sessions(db, user.id)
            changes["password"] = "changed"
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    if body.role_id is not None and body.role_id != user.role_id:
        role = _role(db, actor, body.role_id)
        if user.id == actor.user.id and "users.manage" not in role.permissions:
            raise ApiError(422, "You cannot remove your own user-management access.", {"role_id": "Ask another administrator to change your role."})
        if "users.manage" not in role.permissions and "users.manage" in user.role.permissions and not _admins_left(db, user.id):
            raise ApiError(422, "This is the last administrator.", {"role_id": "Keep at least one enabled administrator."})
        user.role_id = role.id
        changes["role"] = role.name
    if not _reseller(actor) and (body.clear_parent or (body.parent_id is not None and body.parent_id != user.parent_id)):
        if body.parent_id == user.id:
            raise ApiError(422, "A user cannot be its own reseller.", {"parent_id": "Choose another reseller."})
        user.parent_id = None if body.clear_parent else _parent(db, body.parent_id)
        changes["parent_id"] = user.parent_id
    sent = {f: getattr(body, f) for f in QUOTA_FIELDS if f in body.model_fields_set}
    if sent:
        if user.id == actor.user.id and _reseller(actor):
            raise ApiError(422, "Ask an administrator to change your own limits.")
        for field, value in _quotas(actor, sent).items():
            if getattr(user, field) != value:
                setattr(user, field, value)
                changes[field] = value
    if body.reset_two_factor and user.totp_enabled:
        security.disable_two_factor(user)
        security.end_user_sessions(db, user.id)
        changes["two_factor"] = "reset"
    if body.enabled is not None and body.enabled != user.enabled:
        if not body.enabled:
            if user.id == actor.user.id:
                raise ApiError(422, "You cannot disable your own account.", {"enabled": "You cannot disable yourself."})
            if "users.manage" in user.role.permissions and not _admins_left(db, user.id):
                raise ApiError(422, "This is the last administrator.", {"enabled": "Keep at least one enabled administrator."})
            security.end_user_sessions(db, user.id)
        user.enabled = body.enabled
        changes["enabled"] = body.enabled
    audit.record(db, actor.name, "user.updated", "user", user.id, {"username": user.username, "changes": changes}, actor.ip)
    db.commit()
    db.refresh(user)
    return user_out(user, actor.user.id, _zone_count(db, user.id))


@router.delete("/users/{user_id}")
def delete_user(user_id: int, actor: Actor = Depends(manager), db: Session = Depends(get_db)) -> dict:
    user = _target(db, actor, user_id)
    if user.id == actor.user.id:
        raise ApiError(422, "You cannot delete your own account.")
    if "users.manage" in user.role.permissions and user.enabled and not _admins_left(db, user.id):
        raise ApiError(422, "This is the last administrator.")
    audit.record(db, actor.name, "user.deleted", "user", user.id, {"username": user.username}, actor.ip)
    db.delete(user)
    db.commit()
    return {"ok": True}


@router.get("/users/{user_id}/zones")
def user_zone_list(user_id: int, actor: Actor = Depends(manager), db: Session = Depends(get_db)) -> dict:
    user = _target(db, actor, user_id)
    rows = db.execute(select(Zone.id, Zone.name).join(user_zones, user_zones.c.zone_id == Zone.id)
                      .where(user_zones.c.user_id == user.id).order_by(Zone.name)).all()
    return {"zone_scope": user.role.zone_scope, "rows": [{"id": i, "name": n} for i, n in rows]}


@router.put("/users/{user_id}/zones")
def set_user_zones(user_id: int, body: ZonesIn, actor: Actor = Depends(manager), db: Session = Depends(get_db)) -> dict:
    user = _target(db, actor, user_id)
    if user.role.zone_scope != "assigned" and body.zone_ids:
        raise ApiError(422, f"Role {user.role.name} covers every zone; zones are given only to roles limited to their own zones (e.g. customer).")
    added, removed = _set_zones(db, actor, user, body.zone_ids)
    if added or removed:
        audit.record(db, actor.name, "user.zones_changed", "user", user.id, {"username": user.username, "added": added, "removed": removed}, actor.ip)
    db.commit()
    return user_zone_list(user_id, actor, db)


@router.get("/users/{user_id}/tokens")
def user_tokens(user_id: int, actor: Actor = Depends(manager), db: Session = Depends(get_db)) -> dict:
    _target(db, actor, user_id)
    rows = db.scalars(select(ApiToken).where(ApiToken.user_id == user_id).order_by(ApiToken.created_at.desc())).all()
    return {"rows": [token_out(t) for t in rows]}


@router.delete("/users/{user_id}/tokens/{token_id}")
def revoke_user_token(user_id: int, token_id: int, actor: Actor = Depends(manager), db: Session = Depends(get_db)) -> dict:
    _target(db, actor, user_id)
    row = db.get(ApiToken, token_id)
    if row is None or row.user_id != user_id:
        raise not_found("App password")
    audit.record(db, actor.name, "user.app_password_revoked", "api_token", row.id, {"name": row.name, "username": row.user.username}, actor.ip)
    db.delete(row)
    db.commit()
    return {"ok": True}
