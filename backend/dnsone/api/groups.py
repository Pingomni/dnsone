"""Client groups (per-client policies): clients by address or subnet, each group with its own
blocklists and rules. Clients in no group belong to the built-in Default group."""

from __future__ import annotations

import ipaddress

from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit, rpz, runtime, validation
from ..db import get_db
from ..models import Blocklist, ClientGroup, ClientGroupNetwork, RpzRule
from ..security import iso
from .deps import Actor, ApiError, field_error, not_found, require

router = APIRouter(prefix="/api/groups", tags=["groups"])


class GroupIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=255)
    blocking: bool = True
    blocklist_ids: list[int] = Field(default_factory=list)
    # Safe Search (Google, Bing, DuckDuckGo), YouTube restrictions, DNS64.
    safe_search: bool = False
    youtube: Literal["off", "moderate", "strict"] = "off"
    dns64: bool = False


class GroupPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=255)
    blocking: bool | None = None
    blocklist_ids: list[int] | None = None
    safe_search: bool | None = None
    youtube: Literal["off", "moderate", "strict"] | None = None
    dns64: bool | None = None


class NetworkIn(BaseModel):
    network: str = Field(max_length=64)
    comment: str = Field(default="", max_length=255)


class NetworkImport(BaseModel):
    text: str = Field(max_length=1_000_000)


def network_out(n: ClientGroupNetwork) -> dict:
    return {"id": n.id, "network": n.network, "comment": n.comment, "created_at": iso(n.created_at)}


def group_out(db: Session, g: ClientGroup, detail: bool = False) -> dict:
    rules = dict(db.execute(select(RpzRule.match_type, func.count()).where(RpzRule.group_id == g.id).group_by(RpzRule.match_type)).all())
    out = {
        "id": g.id, "name": g.name, "description": g.description, "blocking": g.blocking, "built_in": g.built_in,
        "safe_search": g.safe_search, "youtube": g.youtube, "dns64": g.dns64,
        "networks": db.scalar(select(func.count()).select_from(ClientGroupNetwork).where(ClientGroupNetwork.group_id == g.id)) or 0,
        "blocklists": [{"id": b.id, "name": b.name, "kind": b.kind, "enabled": b.enabled, "domain_count": b.domain_count}
                       for b in sorted(g.blocklists, key=lambda b: (b.kind, b.name))],
        "rules": rules.get("exact", 0), "regex_rules": rules.get("regex", 0),
        "entries": (rpz.get_state(db).get("groups") or {}).get(str(g.id)),
        "updated_at": iso(g.updated_at),
    }
    if detail:
        out["network_list"] = [network_out(n) for n in g.networks]
    return out


def _get(db: Session, group_id: int) -> ClientGroup:
    group = db.get(ClientGroup, group_id)
    if group is None:
        raise not_found("Group")
    return group


def _lists(db: Session, ids: list[int]) -> list[Blocklist]:
    lists = list(db.scalars(select(Blocklist).where(Blocklist.id.in_(ids)))) if ids else []
    if len(lists) != len(set(ids)):
        raise ApiError(422, "One of the chosen blocklists no longer exists.", {"blocklist_ids": "Choose the lists again."})
    return lists


@router.get("")
def list_groups(actor: Actor = Depends(require("rpz.view")), db: Session = Depends(get_db)) -> dict:
    groups = db.scalars(select(ClientGroup).order_by(ClientGroup.built_in.desc(), ClientGroup.name)).all()
    return {"rows": [group_out(db, g) for g in groups]}


@router.get("/lookup")
def lookup_client(client: str = Query(max_length=45), actor: Actor = Depends(require("rpz.view")), db: Session = Depends(get_db)) -> dict:
    """The group a client address is in, and the network that put it there (the most specific)."""
    try:
        address = ipaddress.ip_address(client.strip())
    except ValueError:
        raise ApiError(422, "Enter an IP address.", {"client": "Enter an IP address."}) from None
    best = None
    for n in db.scalars(select(ClientGroupNetwork)):
        net = ipaddress.ip_network(n.network)
        if address.version == net.version and address in net and (best is None or net.prefixlen > ipaddress.ip_network(best.network).prefixlen):
            best = n
    group = best.group if best else db.scalar(select(ClientGroup).where(ClientGroup.built_in.is_(True)))
    return {"client": str(address), "group": {"id": group.id, "name": group.name, "blocking": group.blocking}, "network": best.network if best else None}


@router.get("/{group_id}")
def get_group(group_id: int, actor: Actor = Depends(require("rpz.view")), db: Session = Depends(get_db)) -> dict:
    return group_out(db, _get(db, group_id), detail=True)


@router.post("", status_code=201)
def create_group(body: GroupIn, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    group = ClientGroup(name=body.name.strip(), description=body.description.strip(), blocking=body.blocking, blocklists=_lists(db, body.blocklist_ids),
                        safe_search=body.safe_search, youtube=body.youtube, dns64=body.dns64)
    db.add(group)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "A group with this name already exists.", {"name": "This name is taken."}) from None
    rpz.mark_changed(db)
    audit.record(db, actor.name, "group.created", "group", group.id, {"name": group.name, "blocking": group.blocking,
                 "blocklists": [b.name for b in group.blocklists], "safe_search": group.safe_search, "youtube": group.youtube, "dns64": group.dns64}, actor.ip)
    db.commit()
    background.add_task(rpz.build_in_background)
    return group_out(db, group, detail=True)


@router.patch("/{group_id}")
def update_group(group_id: int, body: GroupPatch, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    group = _get(db, group_id)
    changes: dict = {}
    if body.name is not None and body.name.strip() != group.name:
        if group.built_in:
            raise ApiError(422, "The Default group keeps its name.", {"name": "The Default group keeps its name."})
        changes["name"] = {"from": group.name, "to": body.name.strip()}
        group.name = body.name.strip()
    if body.description is not None:
        group.description = body.description.strip()
    rebuild = False
    if body.blocking is not None and body.blocking != group.blocking:
        changes["blocking"] = body.blocking
        group.blocking = body.blocking
        rebuild = True
    for field in ("safe_search", "youtube"):
        value = getattr(body, field)
        if value is not None and value != getattr(group, field):
            changes[field] = value
            setattr(group, field, value)
            rebuild = True
    if body.dns64 is not None and body.dns64 != group.dns64:
        changes["dns64"] = body.dns64
        group.dns64 = body.dns64
    if body.blocklist_ids is not None:
        lists = _lists(db, body.blocklist_ids)
        before, after = sorted(b.name for b in group.blocklists), sorted(b.name for b in lists)
        if before != after:
            changes["blocklists"] = {"from": before, "to": after}
            group.blocklists = lists
            rebuild = True
    if rebuild:
        rpz.mark_changed(db)
    audit.record(db, actor.name, "group.updated", "group", group.id, {"name": group.name, "changes": changes}, actor.ip)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "A group with this name already exists.", {"name": "This name is taken."}) from None
    background.add_task(rpz.build_in_background if rebuild else runtime.apply_in_background)
    return group_out(db, group, detail=True)


@router.delete("/{group_id}")
def delete_group(group_id: int, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    group = _get(db, group_id)
    if group.built_in:
        raise ApiError(422, "The Default group cannot be deleted: it holds every client in no other group.")
    rules = db.execute(delete(RpzRule).where(RpzRule.group_id == group.id)).rowcount
    audit.record(db, actor.name, "group.deleted", "group", group.id, {"name": group.name, "networks": len(group.networks), "rules": rules}, actor.ip)
    db.delete(group)
    rpz.mark_changed(db)
    db.commit()
    # Its clients move to Default at once (runtime), its RPZ goes with the rebuild.
    background.add_task(runtime.apply_in_background)
    background.add_task(rpz.build_in_background)
    return {"ok": True}


def _add_network(db: Session, group: ClientGroup, raw: str, comment: str, field: str = "network") -> ClientGroupNetwork:
    network = validation.network(raw, field)
    taken = db.scalar(select(ClientGroupNetwork).where(ClientGroupNetwork.network == network))
    if taken is not None:
        where = "this group" if taken.group_id == group.id else f"group {taken.group.name}"
        raise validation.ValidationError(field, f"{network} is already in {where}.")
    row = ClientGroupNetwork(group_id=group.id, network=network, comment=comment.strip())
    db.add(row)
    return row


@router.post("/{group_id}/networks", status_code=201)
def add_network(group_id: int, body: NetworkIn, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    group = _get(db, group_id)
    if group.built_in:
        raise ApiError(422, "The Default group has no networks: it holds every client in no other group.")
    try:
        row = _add_network(db, group, body.network, body.comment)
        db.flush()
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    audit.record(db, actor.name, "group.network_added", "group", group.id, {"name": group.name, "network": row.network}, actor.ip)
    db.commit()
    background.add_task(runtime.apply_in_background)
    return network_out(row)


@router.post("/{group_id}/networks/import")
def import_networks(group_id: int, body: NetworkImport, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    """One address or subnet per line ('#' comments); ones already in a group are reported, not moved."""
    group = _get(db, group_id)
    if group.built_in:
        raise ApiError(422, "The Default group has no networks: it holds every client in no other group.")
    added, skipped = 0, []
    seen: set[str] = set()
    for line in body.text.splitlines():
        token, _, comment = line.partition("#")
        token = token.strip()
        if not token:
            continue
        try:
            network = validation.network(token)
            if network in seen:
                continue
            seen.add(network)
            _add_network(db, group, network, comment)
            added += 1
        except validation.ValidationError as exc:
            skipped.append(exc.message)
    if added > 20000:
        raise ApiError(422, "Import at most 20,000 networks at a time.")
    db.flush()
    audit.record(db, actor.name, "group.networks_imported", "group", group.id, {"name": group.name, "added": added, "skipped": len(skipped)}, actor.ip)
    db.commit()
    if added:
        background.add_task(runtime.apply_in_background)
    return {"added": added, "skipped": skipped[:50], "skipped_count": len(skipped)}


@router.delete("/{group_id}/networks/{network_id}")
def delete_network(group_id: int, network_id: int, background: BackgroundTasks, actor: Actor = Depends(require("rpz.manage")), db: Session = Depends(get_db)) -> dict:
    row = db.get(ClientGroupNetwork, network_id)
    if row is None or row.group_id != group_id:
        raise not_found("Network")
    audit.record(db, actor.name, "group.network_removed", "group", group_id, {"name": row.group.name, "network": row.network}, actor.ip)
    db.delete(row)
    db.commit()
    background.add_task(runtime.apply_in_background)
    return {"ok": True}
