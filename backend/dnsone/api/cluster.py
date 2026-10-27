# SPDX-License-Identifier: Elastic-2.0
# DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
"""Settings → Cluster (Phase 2): the nodes sharing this database, setting the cluster up from the console
(clusterjoin.py), and the BIND secondaries."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, cluster, clusterjoin, validation
from ..config import get_settings
from ..db import get_db
from ..models import Setting
from ..zonegen import Publisher, secondaries, set_secondaries
from .deps import Actor, ApiError, field_error, require

router = APIRouter(prefix="/api/cluster", tags=["cluster"])
# Joining and leaving need no licence of their own: a server joins with the cluster's licence (which must have a
# place for it) and runs with it. Creating a cluster (adding servers) is the Pro router above.
join_router = APIRouter(prefix="/api/cluster", tags=["cluster"])


class Secondary(BaseModel):
    address: str = Field(max_length=45)
    port: int = 5301
    name: str = Field(default="", max_length=64)


class SecondariesIn(BaseModel):
    servers: list[Secondary] = Field(max_length=50)


class ServerIn(BaseModel):
    address: str = Field(max_length=45)
    name: str = Field(default="", max_length=64)
    listen: str = Field(max_length=45)


class JoinIn(BaseModel):
    key: str = Field(max_length=16384)


def _setup_error(exc: Exception) -> ApiError:
    if isinstance(exc, validation.ValidationError):
        return field_error(exc)
    return ApiError(409, str(exc))


def _reconcile() -> None:
    Publisher().reconcile()


@router.get("")
def overview(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    s = get_settings()
    catalog = db.get(Setting, "zonegen.catalog")
    return {
        "node": s.node_name, "role": s.role, "nodes": cluster.nodes(db), "secondaries": secondaries(db),
        "catalog_zone": s.catalog_zone, "catalog_serial": (catalog.value or {}).get("serial") if catalog else None,
        "stale_minutes": cluster.STALE_MINUTES, "setup": clusterjoin.overview(db, s),
    }


@router.post("/servers")
def add_server(body: ServerIn, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    """On the primary: prepares a server to join (its database account, MySQL and BIND reachable from it)."""
    try:
        entry = clusterjoin.add_server(db, body.address, body.name, body.listen)
    except (clusterjoin.ClusterError, validation.ValidationError) as exc:
        db.rollback()
        raise _setup_error(exc) from None
    audit.record(db, actor.name, "cluster.server_added", "settings", entry["address"], {"name": entry["name"], "primary": body.listen}, actor.ip)
    db.commit()
    return {"message": f"Preparing {entry['address']}: its join key appears here in a few seconds."}


@router.get("/servers/{address}/key")
def server_key(address: str, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        key = clusterjoin.join_key(db, address)
    except clusterjoin.ClusterError as exc:
        raise ApiError(409, str(exc)) from None
    audit.record(db, actor.name, "cluster.join_key_shown", "settings", address, None, actor.ip)
    db.commit()
    return {"key": key}


@router.delete("/servers/{address}")
def remove_server(address: str, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        entry = clusterjoin.remove_server(db, address)
    except clusterjoin.ClusterError as exc:
        db.rollback()
        raise ApiError(409, str(exc)) from None
    audit.record(db, actor.name, "cluster.server_removed", "settings", address, {"name": entry.get("name"), "node": entry.get("node")}, actor.ip)
    db.commit()
    return {"message": f"{address} is out of the cluster: its database account is removed."}


@join_router.get("/join")
def join_state(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    """What a server without the cluster feature sees: whether it is a replica, and its last join or leave."""
    s = get_settings()
    return {"node": s.node_name, "role": s.role, "setup": clusterjoin.overview(db, s)}


@join_router.post("/join")
def join(body: JoinIn, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    """On a standalone server: becomes a replica of the primary the key is from."""
    try:
        target = clusterjoin.request_join(db, body.key)
    except clusterjoin.ClusterError as exc:
        raise ApiError(409, str(exc)) from None
    audit.record(db, actor.name, "cluster.join_requested", "settings", target["primary"], target, actor.ip)
    db.commit()
    return {"message": f"Joining the cluster of {target['primary']}: the console restarts in a minute; then sign in with the primary's accounts."}


@join_router.post("/leave")
def leave(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        clusterjoin.request_leave()
    except clusterjoin.ClusterError as exc:
        raise ApiError(409, str(exc)) from None
    audit.record(db, actor.name, "cluster.leave_requested", "settings", get_settings().node_name, None, actor.ip)
    db.commit()
    return {"message": "Leaving the cluster: the console restarts in a minute; then sign in with this server's own accounts."}


@router.put("/secondaries")
def update_secondaries(body: SecondariesIn, background: BackgroundTasks, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    before = secondaries(db)
    try:
        after = set_secondaries(db, [x.model_dump() for x in body.servers])
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    audit.record(db, actor.name, "cluster.secondaries_updated", "settings", "cluster.secondaries", {"from": before, "to": after}, actor.ip)
    db.commit()
    if get_settings().role == "primary":
        background.add_task(_reconcile)
    return {"secondaries": after}


@router.get("/secondary-config", response_class=PlainTextResponse)
def secondary_config(primary: str = Query(max_length=45), port: int = Query(5301, ge=1, le=65535),
                     actor: Actor = Depends(require("system.manage"))) -> str:
    """named.conf lines for a secondary BIND that follows this primary's catalog."""
    try:
        address = str(ipaddress.ip_address(primary.strip()))
    except ValueError:
        raise ApiError(422, "Enter the primary's IP address.", {"primary": "Enter an IP address."}) from None
    return cluster.render_secondary_config(get_settings().catalog_zone, address, port)
