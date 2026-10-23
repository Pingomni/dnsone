"""Sign-in (with an optional second factor), sign-out, the current operator, password changes,
two-factor enrolment and app passwords."""

from __future__ import annotations

import time
from datetime import timedelta

import segno
from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import __version__, audit, oidc, security, validation
from ..config import get_settings
from ..db import get_db
from ..models import ApiToken
from ..security import iso
from ..system import utcnow
from .deps import Actor, ApiError, client_ip, current_actor, field_error, not_found, session_actor

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class PasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class SecondFactorIn(BaseModel):
    ticket: str = Field(max_length=128)
    code: str = Field(max_length=32)


class PasswordConfirm(BaseModel):
    password: str = Field(max_length=256)


class CodeIn(BaseModel):
    code: str = Field(max_length=32)


class DisableIn(BaseModel):
    password: str = Field(max_length=256)
    code: str = Field(max_length=32)


class TokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    read_only: bool = True
    # None: never expires.
    expires_days: int | None = Field(default=None, ge=1, le=3650)


def me_payload(actor_user, permissions: list[str], csrf: str) -> dict:
    s = get_settings()
    return {
        "user": {
            "id": actor_user.id,
            "username": actor_user.username,
            "name": actor_user.name,
            "email": actor_user.email,
            "role": actor_user.role.name,
            "auth_source": actor_user.auth_source,
            "two_factor_enabled": actor_user.totp_enabled,
        },
        "permissions": permissions,
        "csrf": csrf,
        "appVersion": __version__,
        "clock": {"now": int(time.time()), "timezone": s.timezone},
        "node": s.node_name,
    }


def _set_cookies(response: Response, token: str, csrf: str) -> None:
    s = get_settings()
    age = s.session_hours * 3600
    response.set_cookie(security.SESSION_COOKIE, token, max_age=age, httponly=True, secure=s.cookie_secure, samesite="strict", path="/")
    response.set_cookie(security.CSRF_COOKIE, csrf, max_age=age, httponly=False, secure=s.cookie_secure, samesite="strict", path="/")


def _start_session(db: Session, request: Request, response: Response, user, method: str, oidc_id_token: str | None = None) -> dict:
    ip = client_ip(request)
    token, csrf = security.create_session(db, user, ip, request.headers.get("user-agent", ""), oidc_id_token)
    audit.record(db, user.username, "auth.login", "user", user.id, {"method": method}, ip)
    db.commit()
    _set_cookies(response, token, csrf)
    return me_payload(user, list(user.role.permissions or []), csrf)


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    ip = client_ip(request)
    try:
        user = security.authenticate_local(db, body.username, body.password)
    except security.LoginError as exc:
        audit.record(db, body.username.strip().lower()[:64] or "-", "auth.login_failed", "user", "", None, ip)
        db.commit()
        raise ApiError(401, str(exc)) from None
    if user.totp_enabled:
        ticket = security.create_challenge(db, user, ip)
        db.commit()
        return {"two_factor_required": True, "ticket": ticket}
    return _start_session(db, request, response, user, "password")


@router.post("/login/verify")
def login_second_factor(body: SecondFactorIn, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    """The second step of a sign-in: a code from the authenticator app, or a recovery code."""
    ip = client_ip(request)
    challenge = security.resolve_challenge(db, body.ticket)
    if challenge is None:
        raise ApiError(401, "The sign-in timed out or had too many wrong codes. Enter your password again.", {"ticket": "expired"})
    user = challenge.user
    method = security.verify_second_factor(user, body.code)
    if method is None:
        challenge.attempts += 1
        user.failed_logins += 1
        if user.failed_logins >= get_settings().login_max_failures:
            user.locked_until = utcnow() + timedelta(minutes=get_settings().login_lock_minutes)
            user.failed_logins = 0
            db.delete(challenge)
        audit.record(db, user.username, "auth.second_factor_failed", "user", user.id, None, ip)
        db.commit()
        raise ApiError(401, "That code is not right. Use the current code from your authenticator app, or a recovery code.", {"code": "Wrong code."})
    db.delete(challenge)
    user.failed_logins = 0
    if method == "recovery":
        audit.record(db, user.username, "auth.recovery_code_used", "user", user.id, {"left": len(user.recovery_codes or [])}, ip)
    return _start_session(db, request, response, user, method)


@router.get("/oidc")
def oidc_status() -> dict:
    """For the sign-in page: is single sign-on configured, and the button's label."""
    s = get_settings()
    return {"enabled": oidc.enabled(s), "label": s.oidc_label}


def _sso_error(message: str) -> RedirectResponse:
    # The SPA's sign-in page shows ?sso_error=...
    from urllib.parse import quote
    return RedirectResponse(f"/?sso_error={quote(message[:300])}", status_code=303)


@router.get("/oidc/login")
def oidc_login(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    if not oidc.enabled():
        return _sso_error("Single sign-on is not configured on this server.")
    try:
        url = oidc.start(db, client_ip(request))
    except oidc.OidcError as exc:
        return _sso_error(str(exc))
    db.commit()
    return RedirectResponse(url, status_code=303)


@router.get("/oidc/callback")
def oidc_callback(request: Request, state: str = Query("", max_length=64), code: str = Query("", max_length=4096),
                  error: str = Query("", max_length=128), error_description: str = Query("", max_length=512),
                  db: Session = Depends(get_db)) -> RedirectResponse:
    ip = client_ip(request)
    if error:
        return _sso_error("Sign-in cancelled." if error == "access_denied" else f"Keycloak: {error_description or error}")
    try:
        identity = oidc.finish(db, state, code)
        user = oidc.upsert_user(db, identity)
    except oidc.OidcError as exc:
        db.rollback()
        audit.record(db, "-", "auth.sso_failed", "user", "", {"reason": str(exc)[:200]}, ip)
        db.commit()
        return _sso_error(str(exc))
    response = RedirectResponse("/", status_code=303)
    _start_session(db, request, response, user, "sso", identity.id_token)
    return response


@router.post("/logout")
def logout(request: Request, response: Response, actor: Actor = Depends(session_actor), db: Session = Depends(get_db)) -> dict:
    sso_logout = oidc.logout_url(actor.session.oidc_id_token if actor.session else None)
    security.end_session(db, request.cookies.get(security.SESSION_COOKIE))
    audit.record(db, actor.name, "auth.logout", "user", actor.user.id, None, actor.ip)
    db.commit()
    response.delete_cookie(security.SESSION_COOKIE, path="/")
    response.delete_cookie(security.CSRF_COOKIE, path="/")
    # Signed in through Keycloak: the browser goes there next, to end the SSO session too.
    return {"ok": True, "redirect": sso_logout}


@router.get("/me")
def me(actor: Actor = Depends(current_actor)) -> dict:
    return me_payload(actor.user, actor.permissions, actor.session.csrf_token if actor.session else "")


@router.post("/password")
def change_password(body: PasswordIn, request: Request, actor: Actor = Depends(session_actor), db: Session = Depends(get_db)) -> dict:
    user = db.merge(actor.user)
    if user.auth_source != "local":
        raise ApiError(400, "This account signs in through single sign-on; change the password there.")
    if not security.check_password(user, body.current_password):
        raise ApiError(422, "The current password is wrong.", {"current_password": "The current password is wrong."})
    try:
        new = validation.password(body.new_password, "new_password")
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    user.password_hash = security.hash_password(new)
    security.end_user_sessions(db, user.id, keep=request.cookies.get(security.SESSION_COOKIE))
    audit.record(db, actor.name, "user.password_changed", "user", user.id, None, actor.ip)
    db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------- two-factor


def _local_user(db: Session, actor: Actor):
    user = db.merge(actor.user)
    if user.auth_source != "local":
        raise ApiError(400, "This account signs in through single sign-on; set up two-factor there.")
    return user


def _confirm_password(user, password: str) -> None:
    if not security.check_password(user, password):
        raise ApiError(422, "The password is wrong.", {"password": "The password is wrong."})


@router.get("/2fa")
def two_factor_status(actor: Actor = Depends(session_actor)) -> dict:
    return {"enabled": actor.user.totp_enabled, "recovery_codes_left": len(actor.user.recovery_codes or []) if actor.user.totp_enabled else 0}


@router.post("/2fa/setup")
def two_factor_setup(body: PasswordConfirm, actor: Actor = Depends(session_actor), db: Session = Depends(get_db)) -> dict:
    """Starts enrolment: a new secret to scan. Nothing changes for sign-in until /2fa/enable."""
    user = _local_user(db, actor)
    if user.totp_enabled:
        raise ApiError(409, "Two-factor sign-in is already on. Turn it off first to move it to a new device.")
    _confirm_password(user, body.password)
    user.totp_secret = security.totp_new_secret()
    db.commit()
    uri = security.totp_uri(user.totp_secret, user.username)
    return {"secret": user.totp_secret, "uri": uri, "qr": segno.make(uri, error="m").svg_data_uri(scale=5, border=2)}


@router.post("/2fa/enable")
def two_factor_enable(body: CodeIn, request: Request, actor: Actor = Depends(session_actor), db: Session = Depends(get_db)) -> dict:
    user = _local_user(db, actor)
    if user.totp_enabled:
        raise ApiError(409, "Two-factor sign-in is already on.")
    if not user.totp_secret:
        raise ApiError(409, "Start the setup first.")
    step = security.totp_match(user.totp_secret, body.code, None)
    if step is None:
        raise ApiError(422, "That code is not right. Check the time on your phone and enter the current code.", {"code": "Wrong code."})
    user.totp_enabled, user.totp_last_step = True, step
    codes = security.new_recovery_codes(user)
    # Other sessions were signed in with the password alone.
    security.end_user_sessions(db, user.id, keep=request.cookies.get(security.SESSION_COOKIE))
    audit.record(db, actor.name, "user.two_factor_enabled", "user", user.id, None, actor.ip)
    db.commit()
    return {"enabled": True, "recovery_codes": codes}


@router.post("/2fa/disable")
def two_factor_disable(body: DisableIn, actor: Actor = Depends(session_actor), db: Session = Depends(get_db)) -> dict:
    user = _local_user(db, actor)
    if not user.totp_enabled:
        return {"enabled": False}
    _confirm_password(user, body.password)
    if security.verify_second_factor(user, body.code) is None:
        raise ApiError(422, "That code is not right.", {"code": "Wrong code."})
    security.disable_two_factor(user)
    audit.record(db, actor.name, "user.two_factor_disabled", "user", user.id, None, actor.ip)
    db.commit()
    return {"enabled": False}


@router.post("/2fa/recovery-codes")
def two_factor_new_codes(body: PasswordConfirm, actor: Actor = Depends(session_actor), db: Session = Depends(get_db)) -> dict:
    user = _local_user(db, actor)
    if not user.totp_enabled:
        raise ApiError(409, "Turn on two-factor sign-in first.")
    _confirm_password(user, body.password)
    codes = security.new_recovery_codes(user)
    audit.record(db, actor.name, "user.recovery_codes_renewed", "user", user.id, None, actor.ip)
    db.commit()
    return {"recovery_codes": codes}


# --------------------------------------------------------------------------- app passwords


def token_out(t: ApiToken) -> dict:
    return {"id": t.id, "name": t.name, "prefix": t.prefix, "read_only": t.read_only, "created_at": iso(t.created_at),
            "last_used_at": iso(t.last_used_at), "last_used_ip": t.last_used_ip, "expires_at": iso(t.expires_at),
            "expired": bool(t.expires_at and t.expires_at < utcnow())}


@router.get("/tokens")
def list_tokens(actor: Actor = Depends(session_actor), db: Session = Depends(get_db)) -> dict:
    rows = db.scalars(select(ApiToken).where(ApiToken.user_id == actor.user.id).order_by(ApiToken.created_at.desc())).all()
    return {"rows": [token_out(t) for t in rows]}


@router.post("/tokens", status_code=201)
def create_token(body: TokenIn, actor: Actor = Depends(session_actor), db: Session = Depends(get_db)) -> dict:
    if (db.scalar(select(func.count()).select_from(ApiToken).where(ApiToken.user_id == actor.user.id)) or 0) >= 50:
        raise ApiError(422, "You have 50 app passwords; revoke unused ones first.")
    row, token = security.create_token(db, actor.user, body.name.strip(), body.read_only, body.expires_days)
    db.flush()
    audit.record(db, actor.name, "user.app_password_created", "api_token", row.id, {"name": row.name, "read_only": row.read_only,
                 "expires_days": body.expires_days}, actor.ip)
    db.commit()
    return {**token_out(row), "token": token}


@router.delete("/tokens/{token_id}")
def revoke_token(token_id: int, actor: Actor = Depends(session_actor), db: Session = Depends(get_db)) -> dict:
    row = db.get(ApiToken, token_id)
    if row is None or row.user_id != actor.user.id:
        raise not_found("App password")
    audit.record(db, actor.name, "user.app_password_revoked", "api_token", row.id, {"name": row.name}, actor.ip)
    db.delete(row)
    db.commit()
    return {"ok": True}
