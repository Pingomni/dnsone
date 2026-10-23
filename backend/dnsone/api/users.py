"""Operators and roles."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, security, validation
from ..db import get_db
from ..models import ApiToken, Role, User
from ..security import iso
from ..system import utcnow
from .auth import token_out
from .deps import Actor, ApiError, Paging, field_error, like, not_found, require

router = APIRouter(prefix="/api", tags=["users"])

PERMISSIONS = {
    "dashboard.view": "See the dashboard and statistics",
    "zones.view": "See zones and records",
    "zones.manage": "Create, change and delete zones and records",
    "rpz.view": "See blocklists and RPZ rules",
    "rpz.manage": "Change blocklists, RPZ rules and the block policy",
    "queries.view": "See the query log and top lists (who asked for what)",
    "audit.view": "Read the audit log",
    "users.manage": "Manage operators and roles",
    "system.manage": "Open Settings and see system details",
}


class UserIn(BaseModel):
    username: str = Field(max_length=64)
    name: str = Field(default="", max_length=128)
    email: str = Field(default="", max_length=254)
    role_id: int
    password: str = Field(max_length=256)
    enabled: bool = True


class UserPatch(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=254)
    role_id: int | None = None
    password: str | None = Field(default=None, max_length=256)
    enabled: bool | None = None
    # Lost phone: turns two-factor sign-in off so the user can sign in and enrol again.
    reset_two_factor: bool = False


def user_out(u: User, me: int) -> dict:
    return {"id": u.id, "username": u.username, "name": u.name, "email": u.email, "role": u.role.name, "role_id": u.role_id,
            "enabled": u.enabled, "auth_source": u.auth_source, "last_login_at": iso(u.last_login_at),
            "locked": bool(u.locked_until and u.locked_until > utcnow()), "self": u.id == me, "created_at": iso(u.created_at),
            "two_factor_enabled": u.totp_enabled}


def _role(db: Session, role_id: int) -> Role:
    role = db.get(Role, role_id)
    if role is None:
        raise ApiError(422, "Choose a role.", {"role_id": "Choose a role."})
    return role


def _admins_left(db: Session, excluding: int) -> int:
    return db.scalar(
        select(func.count()).select_from(User).join(Role).where(
            User.enabled.is_(True), User.id != excluding, func.json_contains(Role.permissions, '"users.manage"') == 1
        )
    ) or 0


@router.get("/roles")
def roles(actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    rows = db.scalars(select(Role).order_by(Role.id)).all()
    counts = dict(db.execute(select(User.role_id, func.count()).group_by(User.role_id)).all())
    return {
        "roles": [{"id": r.id, "name": r.name, "description": r.description, "permissions": r.permissions, "built_in": r.built_in, "users": counts.get(r.id, 0)} for r in rows],
        "permissions": PERMISSIONS,
    }


@router.get("/users")
def list_users(
    q: str = Query("", max_length=64),
    status: Literal["", "enabled", "disabled"] = "",
    paging: Paging = Depends(),
    actor: Actor = Depends(require("users.manage")),
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(User)
    if q:
        stmt = stmt.where(or_(User.username.like(like(q.strip())), User.name.like(like(q.strip())), User.email.like(like(q.strip()))))
    if status:
        stmt = stmt.where(User.enabled.is_(status == "enabled"))
    result = paging.apply(db, stmt.order_by(User.username), lambda u: user_out(u, actor.user.id))
    result["summary"] = {
        "enabled": db.scalar(select(func.count()).select_from(User).where(User.enabled.is_(True))) or 0,
        "total": db.scalar(select(func.count()).select_from(User)) or 0,
    }
    return result


@router.post("/users", status_code=201)
def create_user(body: UserIn, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        username = validation.username(body.username)
        email = validation.email(body.email)
        password = validation.password(body.password)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    role = _role(db, body.role_id)
    user = User(username=username, name=body.name.strip(), email=email, role_id=role.id, enabled=body.enabled,
                password_hash=security.hash_password(password), auth_source="local")
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "This username is taken.", {"username": "This username is taken."}) from None
    audit.record(db, actor.name, "user.created", "user", user.id, {"username": username, "role": role.name, "enabled": body.enabled}, actor.ip)
    db.commit()
    db.refresh(user)
    return user_out(user, actor.user.id)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatch, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise not_found("User")
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
        role = _role(db, body.role_id)
        if user.id == actor.user.id and "users.manage" not in role.permissions:
            raise ApiError(422, "You cannot remove your own user-management access.", {"role_id": "Ask another administrator to change your role."})
        if "users.manage" not in role.permissions and "users.manage" in user.role.permissions and not _admins_left(db, user.id):
            raise ApiError(422, "This is the last administrator.", {"role_id": "Keep at least one enabled administrator."})
        user.role_id = role.id
        changes["role"] = role.name
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
    return user_out(user, actor.user.id)


@router.delete("/users/{user_id}")
def delete_user(user_id: int, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise not_found("User")
    if user.id == actor.user.id:
        raise ApiError(422, "You cannot delete your own account.")
    if "users.manage" in user.role.permissions and user.enabled and not _admins_left(db, user.id):
        raise ApiError(422, "This is the last administrator.")
    audit.record(db, actor.name, "user.deleted", "user", user.id, {"username": user.username}, actor.ip)
    db.delete(user)
    db.commit()
    return {"ok": True}


@router.get("/users/{user_id}/tokens")
def user_tokens(user_id: int, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    if db.get(User, user_id) is None:
        raise not_found("User")
    rows = db.scalars(select(ApiToken).where(ApiToken.user_id == user_id).order_by(ApiToken.created_at.desc())).all()
    return {"rows": [token_out(t) for t in rows]}


@router.delete("/users/{user_id}/tokens/{token_id}")
def revoke_user_token(user_id: int, token_id: int, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    row = db.get(ApiToken, token_id)
    if row is None or row.user_id != user_id:
        raise not_found("App password")
    audit.record(db, actor.name, "user.app_password_revoked", "api_token", row.id, {"name": row.name, "username": row.user.username}, actor.ip)
    db.delete(row)
    db.commit()
    return {"ok": True}
