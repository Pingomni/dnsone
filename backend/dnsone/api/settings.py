"""Settings → DNS server (client networks, NAT addresses, rate limits), Settings → Privacy and
Settings → Backup (download and restore)."""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import alerts, audit, backup, privacy, rpz, runtime, validation
from ..system import utcnow
from ..zonegen import Publisher
from ..config import get_settings
from ..db import get_db
from ..models import Setting
from .deps import Actor, ApiError, field_error, require

router = APIRouter(prefix="/api/settings", tags=["settings"])
log = logging.getLogger(__name__)

Section = Literal["zones", "ad_blocking", "settings"]


class ServerIn(BaseModel):
    client_networks: list[str] = Field(max_length=10000)
    nat_addresses: list[str] = Field(default_factory=list, max_length=10000)
    client_qps: int
    client_burst: int
    nat_qps: int
    nat_burst: int
    public_authoritative: bool = True


class RestoreIn(BaseModel):
    backup: dict
    sections: list[Section] = Field(min_length=1)


class PrivacyIn(BaseModel):
    level: int = Field(ge=0, le=3)
    retention_hours: int = Field(ge=1, le=24 * 365)


def _server_out(db: Session) -> dict:
    s = get_settings()
    return {
        **runtime.server_settings(db),
        "stored": db.get(Setting, "dns.server") is not None,
        "loopback": runtime.LOOPBACK,
        "legacy_file": str(s.legacy_client_networks_file),
    }


@router.get("/dns-server")
def dns_server(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    return _server_out(db)


@router.put("/dns-server")
def set_dns_server(body: ServerIn, background: BackgroundTasks, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    before = runtime.server_settings(db)
    try:
        after = runtime.set_server_settings(db, body.model_dump())
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    diff = {k: {"from": before.get(k), "to": after[k]} for k in after if before.get(k) != after[k]}
    audit.record(db, actor.name, "settings.dns_server_updated", "settings", "dns.server", {"changes": diff}, actor.ip)
    db.commit()
    background.add_task(runtime.apply_in_background)
    return _server_out(db)


@router.get("/privacy")
def get_privacy(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    return privacy.describe(db)


@router.put("/privacy")
def set_privacy(body: PrivacyIn, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    before = privacy.get(db)
    try:
        after = privacy.store(db, body.level, body.retention_hours)
    except validation.ValidationError as exc:
        raise field_error(exc) from None
    audit.record(db, actor.name, "settings.privacy_updated", "settings", "querylog.privacy", {"from": before, "to": after}, actor.ip)
    db.commit()
    return privacy.describe(db)


@router.get("/alerts")
def get_alerts(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    return {"config": alerts.public_config(db), "active": alerts.overview(db), "nodes": alerts.states(db)}


@router.put("/alerts")
def set_alerts(body: dict, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    before = alerts.public_config(db)
    try:
        after = alerts.store_config(db, body)
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    audit.record(db, actor.name, "settings.alerts_updated", "settings", "alerts.config", {"from": before, "to": after}, actor.ip)
    db.commit()
    return {"config": after, "active": alerts.overview(db), "nodes": alerts.states(db)}


@router.post("/alerts/test")
def test_alerts(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    results = alerts.send_test(db)
    audit.record(db, actor.name, "settings.alerts_tested", "settings", "alerts.config", {"results": results}, actor.ip)
    db.commit()
    return {"results": results}


@router.get("/backup")
def download_backup(
    sections: list[Section] = Query(["zones", "ad_blocking", "settings"]),
    actor: Actor = Depends(require("system.manage")),
    db: Session = Depends(get_db),
) -> JSONResponse:
    data = backup.export(db, sections)
    audit.record(db, actor.name, "settings.backup_downloaded", "settings", "backup", {"sections": data["sections"]}, actor.ip)
    db.commit()
    name = f"dnsone-backup-{data['node']}-{utcnow():%Y%m%d-%H%M}.json"
    return JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _after_restore(sections: list[str]) -> None:
    """Brings BIND, the RPZ and the runtime files in line with the restored data."""
    try:
        if "zones" in sections:
            Publisher().reconcile()
        if "ad_blocking" in sections:
            rpz.Blocklists().refresh_all()
            rpz.RpzBuilder().build()
        runtime.apply()
    except Exception:  # noqa: BLE001 - the timers retry
        log.exception("follow-up after a restore failed")


@router.post("/restore")
def restore_backup(body: RestoreIn, background: BackgroundTasks, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        report = backup.restore(db, body.backup, list(body.sections))
    except backup.RestoreError as exc:
        db.rollback()
        raise ApiError(422, str(exc)) from None
    audit.record(db, actor.name, "settings.backup_restored", "settings", "backup", {**{k: v for k, v in report.items() if k != "skipped"},
                 "skipped": len(report["skipped"]), "from": {"node": body.backup.get("node"), "created_at": body.backup.get("created_at")}}, actor.ip)
    db.commit()
    background.add_task(_after_restore, list(body.sections))
    return {**report, "skipped": report["skipped"][:200], "skipped_count": len(report["skipped"])}
