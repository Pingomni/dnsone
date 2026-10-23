"""Operator authentication: local passwords (Argon2id) and server-side sessions.

Local users can add a second factor: a TOTP code (RFC 6238, any authenticator app) or a one-time
recovery code, asked for after the password through a short-lived sign-in challenge. App passwords
(api_tokens) let scripts call the API with `Authorization: Bearer dno_...`, without a session.

Sign-in sources are pluggable through users.auth_source. Phase 1 ships 'local'. Keycloak (OIDC)
plugs in as a second source: its callback looks the user up by (auth_source='oidc', external_id=sub),
creates or updates the row and its role from the token's roles, and then calls create_session()
exactly like the local login does. Everything after sign-in (sessions, CSRF, permissions, audit)
is shared.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import ApiToken, AuthChallenge, SessionRow, User
from .system import utcnow

SESSION_COOKIE = "dnsone_session"
CSRF_COOKIE = "dnsone_csrf"
CSRF_HEADER = "X-CSRF-Token"

_hasher = PasswordHasher()
# Verified when the user does not exist, so a wrong username takes as long as a wrong password.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class LoginError(Exception):
    pass


def authenticate_local(db: Session, username: str, password: str) -> User:
    s = get_settings()
    user = db.scalar(select(User).where(User.username == username.strip().lower()))
    if user is None or user.auth_source != "local" or not user.password_hash:
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except VerificationError:
            pass
        raise LoginError("Wrong username or password.")
    now = utcnow()
    if user.locked_until and user.locked_until > now:
        minutes = max(1, int((user.locked_until - now).total_seconds() // 60) + 1)
        raise LoginError(f"Too many failed attempts. Try again in {minutes} minute(s).")
    try:
        _hasher.verify(user.password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        user.failed_logins += 1
        if user.failed_logins >= s.login_max_failures:
            user.locked_until = now + timedelta(minutes=s.login_lock_minutes)
            user.failed_logins = 0
        db.commit()
        raise LoginError("Wrong username or password.") from None
    if not user.enabled:
        raise LoginError("This account is disabled. Ask an administrator.")
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = now
    return user


def create_session(db: Session, user: User, ip: str, user_agent: str) -> tuple[str, str]:
    """Returns (session token for the cookie, CSRF token)."""
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = utcnow()
    db.add(SessionRow(
        id=_token_id(token), user_id=user.id, csrf_token=csrf, ip=ip[:45], user_agent=user_agent[:255],
        created_at=now, last_seen_at=now, expires_at=now + timedelta(hours=get_settings().session_hours),
    ))
    db.execute(delete(SessionRow).where(SessionRow.expires_at < now))
    return token, csrf


def resolve_session(db: Session, token: str | None) -> SessionRow | None:
    if not token or len(token) > 128:
        return None
    row = db.get(SessionRow, _token_id(token))
    now = utcnow()
    if row is None or row.expires_at < now or not row.user.enabled:
        return None
    # Sliding expiry, written at most once a minute.
    if now - row.last_seen_at > timedelta(minutes=1):
        row.last_seen_at = now
        row.expires_at = now + timedelta(hours=get_settings().session_hours)
        db.commit()
    return row


def end_session(db: Session, token: str | None) -> None:
    if token:
        db.execute(delete(SessionRow).where(SessionRow.id == _token_id(token)))


def end_user_sessions(db: Session, user_id: int, keep: str | None = None) -> None:
    stmt = delete(SessionRow).where(SessionRow.user_id == user_id)
    if keep:
        stmt = stmt.where(SessionRow.id != _token_id(keep))
    db.execute(stmt)


def check_password(user: User, password: str) -> bool:
    try:
        return bool(user.password_hash) and _hasher.verify(user.password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def iso(value: datetime | None) -> str | None:
    """A UTC DATETIME as 'YYYY-MM-DD HH:MM:SS' in DNSONE_TIMEZONE, the zone the UI labels times with."""
    if not value:
        return None
    try:
        zone = ZoneInfo(get_settings().timezone)
    except (ZoneInfoNotFoundError, ValueError):
        zone = timezone.utc
    return value.replace(tzinfo=timezone.utc).astimezone(zone).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- two-factor (TOTP)

TOTP_PERIOD = 30
TOTP_DIGITS = 6
CHALLENGE_MINUTES = 5
CHALLENGE_ATTEMPTS = 5
RECOVERY_CODES = 10


def totp_new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_code(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**TOTP_DIGITS).zfill(TOTP_DIGITS)


def totp_uri(secret: str, username: str, issuer: str = "DNSOne") -> str:
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"


def totp_match(secret: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """The time step the code belongs to (one step of clock drift either way), or None.

    A step at or before last_step is refused: a code works once.
    """
    code = code.strip().replace(" ", "")
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None
    current = int((now or time.time()) // TOTP_PERIOD)
    for step in (current - 1, current, current + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp_code(secret, step), code):
            return step
    return None


def _code_hash(code: str) -> str:
    return hashlib.sha256(code.strip().lower().replace("-", "").encode()).hexdigest()


def new_recovery_codes(user: User) -> list[str]:
    """Replaces the user's recovery codes; returns them (shown once)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    user.recovery_codes = [_code_hash(c) for c in codes]
    return codes


def verify_second_factor(user: User, code: str) -> str | None:
    """'totp' or 'recovery' if the code is right (and consumes it), else None."""
    if not user.totp_enabled or not user.totp_secret:
        return None
    step = totp_match(user.totp_secret, code, user.totp_last_step)
    if step is not None:
        user.totp_last_step = step
        return "totp"
    digest = _code_hash(code)
    remaining = list(user.recovery_codes or [])
    for stored in remaining:
        if hmac.compare_digest(stored, digest):
            remaining.remove(stored)
            user.recovery_codes = remaining
            return "recovery"
    return None


def disable_two_factor(user: User) -> None:
    user.totp_secret = None
    user.totp_enabled = False
    user.totp_last_step = None
    user.recovery_codes = None


def create_challenge(db: Session, user: User, ip: str) -> str:
    """A sign-in that passed the password and waits for the second factor."""
    token = secrets.token_urlsafe(32)
    now = utcnow()
    db.execute(delete(AuthChallenge).where(AuthChallenge.expires_at < now))
    db.add(AuthChallenge(id=_token_id(token), user_id=user.id, ip=ip[:45], created_at=now, expires_at=now + timedelta(minutes=CHALLENGE_MINUTES)))
    return token


def resolve_challenge(db: Session, token: str) -> AuthChallenge | None:
    if not token or len(token) > 128:
        return None
    row = db.get(AuthChallenge, _token_id(token))
    if row is None or row.expires_at < utcnow() or row.attempts >= CHALLENGE_ATTEMPTS or not row.user.enabled:
        return None
    return row


# --------------------------------------------------------------------------- app passwords

TOKEN_PREFIX = "dno_"


def create_token(db: Session, user: User, name: str, read_only: bool, expires_days: int | None) -> tuple[ApiToken, str]:
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(user_id=user.id, name=name, token_hash=_token_id(token), prefix=token[:12], read_only=read_only,
                   expires_at=utcnow() + timedelta(days=expires_days) if expires_days else None)
    db.add(row)
    return row, token


def resolve_token(db: Session, token: str, ip: str) -> ApiToken | None:
    if not token.startswith(TOKEN_PREFIX) or len(token) > 128:
        return None
    row = db.scalar(select(ApiToken).where(ApiToken.token_hash == _token_id(token)))
    now = utcnow()
    if row is None or (row.expires_at and row.expires_at < now) or not row.user.enabled:
        return None
    if row.last_used_at is None or now - row.last_used_at > timedelta(minutes=1) or row.last_used_ip != ip[:45]:
        row.last_used_at, row.last_used_ip = now, ip[:45]
        db.commit()
    return row
