"""Settings → Cluster (Phase 2): the nodes sharing this database, and the BIND secondaries."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import audit, cluster, validation
from ..config import get_settings
from ..db import get_db
from ..models import Setting
from ..zonegen import Publisher, secondaries, set_secondaries
from .deps import Actor, ApiError, field_error, require

router = APIRouter(prefix="/api/cluster", tags=["cluster"])


class Secondary(BaseModel):
    address: str = Field(max_length=45)
    port: int = 5301
    name: str = Field(default="", max_length=64)


class SecondariesIn(BaseModel):
    servers: list[Secondary] = Field(max_length=50)


def _reconcile() -> None:
    Publisher().reconcile()


@router.get("")
def overview(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    s = get_settings()
    catalog = db.get(Setting, "zonegen.catalog")
    return {
        "node": s.node_name, "role": s.role, "nodes": cluster.nodes(db), "secondaries": secondaries(db),
        "catalog_zone": s.catalog_zone, "catalog_serial": (catalog.value or {}).get("serial") if catalog else None,
        "stale_minutes": cluster.STALE_MINUTES,
    }


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
