"""DNSOne Pro licences: a key signed by PingOmni, pasted under Settings → License (stored in MySQL).

A key is `DNSONE1.<payload>.<signature>`: the payload is JSON (base64url) and the signature Ed25519 over
it, checked here against PingOmni's public key, with no network. The payload names the customer, the
Pro features ("all" or a list, see FEATURES), the expiry date and the server it is for. tools/issue-license.py
makes keys.

A key is for one server, or for one cluster: it names a server ID (server_id(): derived from the machine's
/etc/machine-id, shown under Settings → License; for a cluster, the primary's) and how many servers it
covers ("servers", 1 by default). It is stored once in the shared database, so every node of a cluster runs
with it; a node's heartbeat carries its server ID, which is how the cluster's servers are told apart and
counted (covered()). More servers than the key covers only warns: DNS never changes because of a licence.
Keys from the PingOmni account (1.5.13) carry "servers" and no server ID: they cover that many servers in the
cluster they are installed in; the account itself knows the server, from its registration (activation.py).
Keys from before 1.5.12 name neither, and cover any number.

States, and what each lets the Pro features do (edition.py):
  none     no key (or an invalid one): DNSOne Community. The Pro features are off.
  valid    every licensed feature works.
  expired  the Pro features keep running as they were, so DNS answers do not change (court orders stay
           blocked, transfers and protection keep applying), but they cannot be changed until renewal.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
from datetime import date, datetime, timedelta, timezone
from functools import cache

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
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
SERVER_ID = re.compile(r"DNS1(?:-[A-Z2-7]{4}){4}\Z")

_cache: tuple[float, dict] | None = None


class LicenseError(ValueError):
    pass


@cache
def server_id() -> str:
    """This server's ID for its licence: stable while the operating system is installed, and not the machine
    ID itself (a hash of it). Without /etc/machine-id, from the node name."""
    from .config import get_settings
    try:
        seed = get_settings().machine_id_file.read_text().strip()
    except OSError:
        seed = ""
    digest = hashlib.sha256(f"dnsone-server:{seed or get_settings().node_name}".encode()).digest()
    code = base64.b32encode(digest).decode()[:16]
    return "DNS1-" + "-".join(code[i:i + 4] for i in range(0, 16, 4))


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
    server = data.get("server")
    # "servers": with a server ID, 1 by default; without one (keys from the PingOmni account), only when given.
    raw = data.get("servers", 1 if server is not None else None)
    try:
        servers = None if raw is None else int(raw) if not isinstance(raw, bool) and float(raw).is_integer() else 0
    except (TypeError, ValueError):
        servers = 0
    if servers is not None and servers < 1:
        raise LicenseError("The licence key is damaged: copy it again, whole.")
    if server is not None and not SERVER_ID.match(str(server)):
        raise LicenseError("The licence key is damaged: copy it again, whole.")
    return {"id": str(data.get("id", "")), "customer": str(data.get("customer", "")), "issued": str(data.get("issued", "")),
            "expires": expires.isoformat(), "features": features, "server": server, "servers": servers}


def describe(payload: dict | None, today: date | None = None) -> dict:
    """The state of a payload (None: no licence), for the console and edition.py."""
    if payload is None:
        return {"state": "none", "features": [], "customer": None, "expires": None, "id": None, "server": None, "servers": None}
    today = today or date.today()
    state = "valid" if date.fromisoformat(payload["expires"]) >= today else "expired"
    return {**payload, "state": state, "days_left": (date.fromisoformat(payload["expires"]) - today).days}


def cluster_servers(db: Session, recent_hours: int | None = None) -> list[str]:
    """The server IDs of the nodes sharing this database (from their heartbeats), this one first; with
    recent_hours, only nodes heard from in that time (a server taken away stops counting)."""
    since = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=recent_hours)).isoformat() if recent_hours else ""
    ids = [server_id()]
    for row in db.scalars(select(Setting).where(Setting.name.like("node.%"))):
        value = row.value or {}
        sid = value.get("server_id")
        if sid and sid not in ids and str(value.get("last_seen", "")) >= since:
            ids.append(sid)
    return ids


def get(db: Session) -> dict:
    """This server's licence as stored, verified again (a key that no longer verifies, or is for a server
    outside this cluster, counts as none)."""
    row = db.get(Setting, KEY)
    text = (row.value or {}).get("key") if row else None
    if not text:
        return describe(None)
    try:
        payload = parse(text)
        if payload["server"] is not None and payload["server"] not in cluster_servers(db):
            raise LicenseError(f"it is for server {payload['server']}, which is not in this cluster")
        return describe(payload)
    except LicenseError as exc:
        log.warning("stored licence key ignored: %s", exc)
        return {**describe(None), "error": str(exc)}


def covered(db: Session, lic: dict) -> dict:
    """How many servers the licence covers and how many run with it."""
    count = len(cluster_servers(db, recent_hours=24))
    return {"servers_used": count, "servers_licensed": lic.get("servers"),
            "over": lic.get("servers") is not None and count > lic["servers"]}


def room(text: str | None, nodes: list[dict], joining: str, recent_hours: int = 24) -> str | None:
    """Whether a cluster's licence (its stored key, and its nodes' heartbeats) has a place for the server
    `joining`: None if it has, else why not. Used before a server joins, against the primary's database."""
    if not text:
        return "The cluster has no DNSOne Pro licence. Add one on its primary (Settings → License) first."
    try:
        lic = describe(parse(text))
    except LicenseError as exc:
        return f"The cluster's licence is not valid: {exc}"
    if lic["state"] != "valid":
        return f"The cluster's licence expired on {lic['expires']}: renew it on the primary first."
    if lic["servers"] is None:
        return None
    since = (datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=recent_hours)).isoformat()
    ids = {n.get("server_id") for n in nodes if n.get("server_id") and str(n.get("last_seen", "")) >= since}
    if joining in ids or len(ids) < lic["servers"]:
        return None
    return (f"The cluster's licence covers {lic['servers']} server{'s' if lic['servers'] != 1 else ''} and "
            f"{len(ids)} {'are' if len(ids) != 1 else 'is'} in use: ask for a licence for {len(ids) + 1}, or add servers to it "
            "in your PingOmni account (account.pingomni.com, the licence's Servers tab).")


def store(db: Session, text: str) -> dict:
    payload = parse(text)
    if payload["server"] is not None and payload["server"] not in cluster_servers(db):
        raise LicenseError(f"This licence is for server {payload['server']}, and this server is {server_id()}. "
                           "Ask for a licence for this server's ID (in a cluster, any of its servers').")
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
