"""DNSOne Pro licences: a key signed by PingOmni, pasted under Settings → License (stored in MySQL).

A key is `DNSONE1.<payload>.<signature>`: the payload is JSON (base64url) and the signature Ed25519 over
it, checked here against PingOmni's public key, with no network. The payload names the customer, the
Pro features ("all" or a list, see FEATURES) and the expiry date. tools/issue-license.py makes keys.

States, and what each lets the Pro features do (edition.py):
  none     no key (or an invalid one): DNSOne Community. The Pro features are off.
  valid    every licensed feature works.
  expired  the Pro features keep running as they were, so DNS answers do not change (court orders stay
           blocked, transfers and protection keep applying), but they cannot be changed until renewal.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
from datetime import date

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session

from .models import Setting

log = logging.getLogger(__name__)

KEY = "license"
PREFIX = "DNSONE1."
FEATURES = ("protection", "firewall", "transfers", "quota", "legal", "oidc", "logexport", "cluster")
# PingOmni's licence signing key (the private half never leaves PingOmni).
PUBLIC_KEYS = ["rpqda1rxFGTFKNyIsZZZhtqQ3Yj2ftn2d/RADOhGeh8="]
# The test suite signs its own keys (backend/tests); set only there.
if os.environ.get("DNSONE_LICENSE_TEST_PUBLIC_KEY"):
    PUBLIC_KEYS.append(os.environ["DNSONE_LICENSE_TEST_PUBLIC_KEY"])
CACHE_SECONDS = 30

_cache: tuple[float, dict] | None = None


class LicenseError(ValueError):
    pass


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parse(text: str) -> dict:
    """The verified payload of a key; LicenseError if it is not a valid DNSOne licence."""
    key = "".join(text.split())
    if not key.startswith(PREFIX) or key.count(".") != 2:
        raise LicenseError("This is not a DNSOne licence key (it starts with DNSONE1.).")
    _, payload_b64, signature_b64 = key.split(".")
    try:
        payload, signature = _b64decode(payload_b64), _b64decode(signature_b64)
    except (ValueError, TypeError):
        raise LicenseError("The licence key is damaged: copy it again, whole.") from None
    for public in PUBLIC_KEYS:
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(public)).verify(signature, payload)
            break
        except (InvalidSignature, ValueError):
            continue
    else:
        raise LicenseError("The licence key is not signed by PingOmni.")
    try:
        data = json.loads(payload)
        expires = date.fromisoformat(data["expires"])
        features = data.get("features") or []
    except (ValueError, KeyError, TypeError):
        raise LicenseError("The licence key is damaged: copy it again, whole.") from None
    features = list(FEATURES) if features == ["all"] else [f for f in features if f in FEATURES]
    return {"id": str(data.get("id", "")), "customer": str(data.get("customer", "")), "issued": str(data.get("issued", "")),
            "expires": expires.isoformat(), "features": features}


def describe(payload: dict | None, today: date | None = None) -> dict:
    """The state of a payload (None: no licence), for the console and edition.py."""
    if payload is None:
        return {"state": "none", "features": [], "customer": None, "expires": None, "id": None}
    today = today or date.today()
    state = "valid" if date.fromisoformat(payload["expires"]) >= today else "expired"
    return {**payload, "state": state, "days_left": (date.fromisoformat(payload["expires"]) - today).days}


def get(db: Session) -> dict:
    """This server's licence as stored, verified again (a key that no longer verifies counts as none)."""
    row = db.get(Setting, KEY)
    text = (row.value or {}).get("key") if row else None
    if not text:
        return describe(None)
    try:
        return describe(parse(text))
    except LicenseError as exc:
        log.warning("stored licence key ignored: %s", exc)
        return {**describe(None), "error": str(exc)}


def store(db: Session, text: str) -> dict:
    payload = parse(text)
    row = db.get(Setting, KEY)
    value = {"key": "".join(text.split())}
    if row is None:
        db.add(Setting(name=KEY, value=value))
    else:
        row.value = value
    invalidate()
    return describe(payload)


def remove(db: Session) -> None:
    row = db.get(Setting, KEY)
    if row is not None:
        db.delete(row)
    invalidate()


def invalidate() -> None:
    global _cache
    _cache = None


def current() -> dict:
    """This server's licence, read from MySQL at most every CACHE_SECONDS (every process: API, query log, jobs)."""
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < CACHE_SECONDS:
        return _cache[1]
    from .db import new_session
    try:
        db = new_session()
        try:
            value = get(db)
        finally:
            db.close()
    except Exception as exc:  # the database is down: keep what we knew, so DNS behaviour does not change
        if _cache is not None:
            return _cache[1]
        log.warning("licence not read: %s", exc)
        value = describe(None)
    _cache = (now, value)
    return value


def allows(feature: str, write: bool = False) -> bool:
    """Is the Pro feature on (running), and with write=True may it be changed?"""
    lic = current()
    if feature not in lic["features"]:
        return False
    return lic["state"] == "valid" if write else lic["state"] in ("valid", "expired")
