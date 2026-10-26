"""Request dependencies shared by the routers: session, permissions, CSRF, errors and paging."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, HTTPException, Query, Request
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from ..edition import pro

quota = pro("quota")
from ..db import get_db
from ..models import ApiToken, SessionRow, User, Zone, user_zones
from ..security import CSRF_HEADER, SESSION_COOKIE, resolve_session, resolve_token
from ..validation import ValidationError

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class ApiError(HTTPException):
    """Error body for the UI: {"message": ..., "errors": {field: message}}."""

    def __init__(self, status: int, message: str, errors: dict[str, str] | None = None, headers: dict[str, str] | None = None):
        super().__init__(status_code=status, detail={"message": message, "errors": errors or {}}, headers=headers)


def field_error(exc: ValidationError) -> ApiError:
    return ApiError(422, exc.message, {exc.field: exc.message})


def quota_error(exc) -> ApiError:
    return ApiError(422, exc.message, {exc.field: exc.message})


def not_found(what: str) -> ApiError:
    return ApiError(404, f"{what} not found.")


@dataclass
class Actor:
    """Who is calling: a signed-in operator (session) or a script with an app password (token)."""

    user: User
    session: SessionRow | None
    ip: str
    token: ApiToken | None = None

    @property
    def name(self) -> str:
        return self.user.username

    @property
    def permissions(self) -> list[str]:
        return list(self.user.role.permissions or [])

    def can(self, permission: str) -> bool:
        return permission in self.permissions

    @property
    def all_zones(self) -> bool:
        """False for customers and resellers: their zone permissions cover only their own zones."""
        return self.user.role.zone_scope != "assigned"

    def zone_ids(self, db: Session) -> set[int] | None:
        """The zones this caller may see: None for every zone, else the assigned ones."""
        if self.all_zones:
            return None
        return set(db.scalars(select(user_zones.c.zone_id).where(user_zones.c.user_id == self.user.id)))

    def zone_filter(self, stmt: Select) -> Select:
        """Limits a query on zones to the caller's."""
        if self.all_zones:
            return stmt
        return stmt.where(Zone.id.in_(select(user_zones.c.zone_id).where(user_zones.c.user_id == self.user.id)))

    def may_zone(self, db: Session, zone_id: int) -> bool:
        if self.all_zones:
            return True
        return db.scalar(select(func.count()).select_from(user_zones).where(user_zones.c.user_id == self.user.id, user_zones.c.zone_id == zone_id)) == 1


def client_ip(request: Request) -> str:
    # uvicorn runs with --proxy-headers and trusts only nginx on loopback, so this is the real client.
    return request.client.host if request.client else ""


def current_actor(request: Request, db: Session = Depends(get_db)) -> Actor:
    actor = _authenticate(request, db)
    wait = quota.check_rate(actor.user) if quota is not None else None
    if wait is not None:
        raise ApiError(429, f"Too many requests: your account allows {actor.user.api_rate} a minute. Try again in {wait} s.", headers={"Retry-After": str(wait)})
    return actor


def _authenticate(request: Request, db: Session) -> Actor:
    authorization = request.headers.get("authorization", "")
    if authorization[:7].lower() == "bearer ":
        # App password: no cookie, so no CSRF risk; a read-only one may only read.
        token = resolve_token(db, authorization[7:].strip(), client_ip(request))
        if token is None:
            raise ApiError(401, "This app password is not valid (revoked, expired, or its user is disabled).")
        if token.read_only and request.method not in SAFE_METHODS:
            raise ApiError(403, "This app password is read-only.")
        return Actor(user=token.user, session=None, ip=client_ip(request), token=token)
    row = resolve_session(db, request.cookies.get(SESSION_COOKIE))
    if row is None:
        raise ApiError(401, "Your session has expired. Sign in again.")
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or sent != row.csrf_token:
            raise ApiError(403, "The request was missing its security token. Reload the page and try again.")
    return Actor(user=row.user, session=row, ip=client_ip(request))


def session_actor(actor: Actor = Depends(current_actor)) -> Actor:
    """Account security (password, two-factor, app passwords) needs a signed-in operator, not a token."""
    if actor.session is None:
        raise ApiError(403, "Sign in to the console for this; app passwords cannot change account security.")
    return actor


def require(permission: str):
    def dependency(actor: Actor = Depends(current_actor)) -> Actor:
        if not actor.can(permission):
            raise ApiError(403, "Your role does not allow this.")
        return actor

    return dependency


class Paging:
    def __init__(self, page: int = Query(1, ge=1, le=100000), size: int = Query(50, ge=1, le=500)):
        self.page = page
        self.size = size

    def apply(self, db: Session, stmt: Select, serialize) -> dict[str, Any]:
        total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
        pages = max(1, math.ceil(total / self.size))
        page = min(self.page, pages)
        rows = db.scalars(stmt.limit(self.size).offset((page - 1) * self.size)).unique().all()
        return {"rows": [serialize(r) for r in rows], "total": total, "page": page, "pages": pages, "size": self.size}


def like(term: str, prefix: bool = False) -> str:
    """A LIKE pattern for a search term (anywhere, or at the start), with %, _ and \\ escaped."""
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"{escaped}%" if prefix else f"%{escaped}%"
