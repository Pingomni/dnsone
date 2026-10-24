"""Dynamic DNS keys of a zone (Zone → Dynamic DNS), and the dyndns2 endpoint routers call."""

from __future__ import annotations

import base64
import binascii
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, ddns, runtime, validation
from ..db import get_db
from ..models import DdnsKey
from ..security import iso
from .deps import Actor, ApiError, client_ip, field_error, not_found, require
from .zones import _zone

router = APIRouter(tags=["ddns"])

Algorithm = Literal["hmac-sha256", "hmac-sha512", "hmac-sha384", "hmac-sha224", "hmac-sha1"]


class KeyIn(BaseModel):
    name: str = Field(max_length=253)
    algorithm: Algorithm = "hmac-sha256"
    # Empty: a new random 256-bit secret.
    secret: str = Field(default="", max_length=128)
    names: list[str] = Field(max_length=100)
    types: list[str] = Field(max_length=20)
    comment: str = Field(default="", max_length=255)


class KeyPatch(BaseModel):
    names: list[str] | None = Field(default=None, max_length=100)
    types: list[str] | None = Field(default=None, max_length=20)
    enabled: bool | None = None
    comment: str | None = Field(default=None, max_length=255)
    new_secret: bool = False


def key_out(k: DdnsKey, secret: bool = False) -> dict:
    out = {"id": k.id, "name": k.name, "algorithm": k.algorithm, "names": k.names, "types": k.types, "enabled": k.enabled, "comment": k.comment,
           "created_by": k.created_by, "created_at": iso(k.created_at), "last_used_at": iso(k.last_used_at), "last_used_ip": k.last_used_ip}
    if secret:
        out["secret"] = k.secret
    return out


def _key(db: Session, zone_id: int, key_id: int) -> DdnsKey:
    key = db.get(DdnsKey, key_id)
    if key is None or key.zone_id != zone_id:
        raise not_found("Key")
    return key


@router.get("/api/zones/{zone_id}/ddns-keys")
def list_keys(zone_id: int, actor: Actor = Depends(require("zones.view")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id)
    rows = db.scalars(select(DdnsKey).where(DdnsKey.zone_id == zone.id).order_by(DdnsKey.name))
    server = runtime.server_settings(db)
    return {"rows": [key_out(k) for k in rows], "mode": server.get("ddns", "off"), "types": list(ddns.TYPES)}


@router.post("/api/zones/{zone_id}/ddns-keys", status_code=201)
def create_key(zone_id: int, body: KeyIn, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id)
    try:
        name = ddns.key_name(body.name, zone.name)
        secret = ddns.clean_secret(body.secret) if body.secret.strip() else ddns.new_secret()
        names = ddns.clean_names(body.names, zone.name)
        types = ddns.clean_types(body.types)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    key = DdnsKey(zone_id=zone.id, name=name, algorithm=body.algorithm, secret=secret, names=names, types=types, comment=body.comment.strip(),
                  created_by=actor.name)
    db.add(key)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "A key with this name already exists (key names are unique on the server).", {"name": "This name is taken."}) from None
    audit.record(db, actor.name, "ddns_key.created", "zone", zone.id, {"name": zone.name, "key": name, "names": names, "types": types}, actor.ip)
    db.commit()
    return key_out(key, secret=True)


@router.patch("/api/zones/{zone_id}/ddns-keys/{key_id}")
def update_key(zone_id: int, key_id: int, body: KeyPatch, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id)
    key = _key(db, zone.id, key_id)
    before = key_out(key)
    try:
        if body.names is not None:
            key.names = ddns.clean_names(body.names, zone.name)
        if body.types is not None:
            key.types = ddns.clean_types(body.types)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    if body.enabled is not None:
        key.enabled = body.enabled
    if body.comment is not None:
        key.comment = body.comment.strip()
    if body.new_secret:
        key.secret = ddns.new_secret()
    after = key_out(key)
    changes = {k: {"from": before[k], "to": after[k]} for k in ("names", "types", "enabled", "comment") if before[k] != after[k]}
    if body.new_secret:
        changes["secret"] = "renewed"
    audit.record(db, actor.name, "ddns_key.updated", "zone", zone.id, {"name": zone.name, "key": key.name, "changes": changes}, actor.ip)
    db.commit()
    return key_out(key, secret=body.new_secret)


@router.delete("/api/zones/{zone_id}/ddns-keys/{key_id}")
def delete_key(zone_id: int, key_id: int, actor: Actor = Depends(require("zones.manage")), db: Session = Depends(get_db)) -> dict:
    zone = _zone(db, actor, zone_id)
    key = _key(db, zone.id, key_id)
    audit.record(db, actor.name, "ddns_key.deleted", "zone", zone.id, {"name": zone.name, "key": key.name}, actor.ip)
    db.delete(key)
    db.commit()
    return {"ok": True}


@router.get("/api/ddns/nic/update", response_class=PlainTextResponse, include_in_schema=False)
def nic_update(request: Request, hostname: str = Query("", max_length=253), myip: str = Query("", max_length=200),
               myipv6: str = Query("", max_length=100), db: Session = Depends(get_db)) -> PlainTextResponse:
    """The dyndns2 protocol (routers' "custom" dynamic DNS): HTTP basic auth with the key's name and secret."""
    auth = request.headers.get("authorization", "")
    user = password = ""
    if auth[:6].lower() == "basic ":
        try:
            user, _, password = base64.b64decode(auth[6:].strip()).decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError):
            pass
    if not user:
        return PlainTextResponse("badauth", status_code=401, headers={"WWW-Authenticate": 'Basic realm="DNSOne dynamic DNS"'})
    addresses = [a for a in myip.split(",") if a.strip()] + [a for a in myipv6.split(",") if a.strip()]
    if not addresses:
        addresses = [client_ip(request)]
    # Some routers send several host names at once; answer one line each.
    answers = [ddns.dyndns2(db, user, password, host, addresses, client_ip(request)) for host in (hostname.split(",") if hostname else [""])[:10]]
    return PlainTextResponse("\n".join(answers), status_code=401 if answers and all(a == "badauth" for a in answers) else 200)
