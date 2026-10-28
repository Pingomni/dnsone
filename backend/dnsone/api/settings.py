"""Settings → DNS server (client networks, NAT addresses, rate limits), Settings → Privacy and
Settings → Backup (download and restore)."""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import __version__, activation, alerts, audit, backup, edition, license, privacy, rpz, runtime, updates, validation
from ..edition import pro

logexport, oidc = pro("logexport"), pro("oidc")
from ..system import utcnow
from ..zonegen import Publisher
from ..config import get_settings
from ..db import get_db
from ..models import Role, Setting
from .deps import Actor, ApiError, field_error, require

router = APIRouter(prefix="/api/settings", tags=["settings"])
log = logging.getLogger(__name__)

Section = Literal["zones", "ad_blocking", "settings", "legal"]


class ServerIn(BaseModel):
    client_networks: list[str] = Field(max_length=10000)
    nat_addresses: list[str] = Field(default_factory=list, max_length=10000)
    client_qps: int
    client_burst: int
    nat_qps: int
    nat_burst: int
    public_authoritative: bool = True
    dns64_prefix: str = Field(default="64:ff9b::/96", max_length=49)
    ddns: Literal["off", "customers", "everyone"] = "off"


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


class EcsIn(BaseModel):
    enabled: bool = False
    domains: list[str] = Field(default_factory=list, max_length=500)
    ipv4_bits: int = 24
    ipv6_bits: int = 56


class ResolverIn(BaseModel):
    serve_stale_hours: int
    ecs: EcsIn


@router.get("/resolver")
def resolver(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    return {**runtime.resolver_settings(db), "max_stale_hours": runtime.MAX_STALE_HOURS}


@router.put("/resolver")
def set_resolver(body: ResolverIn, background: BackgroundTasks, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    """ECS and serve-stale: applied by restarting the Recursor on every node (its cache starts empty)."""
    before = runtime.resolver_settings(db)
    try:
        after = runtime.set_resolver_settings(db, body.model_dump())
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    audit.record(db, actor.name, "settings.resolver_updated", "settings", runtime.RESOLVER_KEY, {"from": before, "to": after}, actor.ip)
    db.commit()
    if after != before:
        background.add_task(runtime.apply_in_background)
    return {**after, "max_stale_hours": runtime.MAX_STALE_HOURS}


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


def _need(module, feature: str, write: bool = False) -> None:
    edition.require(module, feature, write)


class LicenseIn(BaseModel):
    key: str = Field(max_length=4096)


def _license_out(db: Session) -> dict:
    lic = license.get(db)
    return {**lic, **license.covered(db, lic), "server_id": license.server_id(),
            "all_features": {f: edition.FEATURE_NAMES[f] for f in license.FEATURES}, "activation": activation.public(db)}


@router.get("/license")
def get_license(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    return _license_out(db)


def _license_changed() -> None:
    """The Pro features just turned on or off: rewrite what the DNS daemons run with."""
    from ..db import session_scope
    with session_scope() as db:
        rpz.mark_changed(db)
        Publisher().sync_server_config(db)
    runtime.apply_in_background()
    rpz.build_in_background()


@router.put("/license")
def set_license(body: LicenseIn, background: BackgroundTasks, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        lic = license.store(db, body.key)
    except license.LicenseError as exc:
        raise ApiError(422, str(exc), {"key": str(exc)}) from None
    audit.record(db, actor.name, "settings.license_installed", "settings", license.KEY,
                 {"id": lic["id"], "customer": lic["customer"], "expires": lic["expires"], "features": lic["features"],
                  "server": lic["server"], "servers": lic["servers"]}, actor.ip)
    db.commit()
    background.add_task(_license_changed)
    return _license_out(db)


@router.delete("/license")
def delete_license(background: BackgroundTasks, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    license.remove(db)
    audit.record(db, actor.name, "settings.license_removed", "settings", license.KEY, None, actor.ip)
    db.commit()
    background.add_task(_license_changed)
    return _license_out(db)


@router.get("/export")
def get_export(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    _need(logexport, "Query log export")
    return {**logexport.get(db), "nodes": _export_state(db)}


def _export_state(db: Session) -> list[dict]:
    from sqlalchemy import select
    rows = db.scalars(select(Setting).where(Setting.name.like("querylog.state.%")))
    return [{"node": r.value.get("node"), "export": r.value.get("export"), "updated_at": r.value.get("updated_at")} for r in rows]


@router.put("/export")
def set_export(body: dict, background: BackgroundTasks, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    _need(logexport, "Query log export", write=True)
    before = logexport.get(db)
    try:
        after = logexport.store(db, body)
    except (validation.ValidationError, TypeError, ValueError) as exc:
        db.rollback()
        if isinstance(exc, validation.ValidationError):
            raise field_error(exc) from None
        raise ApiError(422, "The export settings are not in the expected form.") from None
    audit.record(db, actor.name, "settings.export_updated", "settings", logexport.KEY, {"from": before, "to": after}, actor.ip)
    db.commit()
    # dnstap lives in dnsdist's settings file; syslog is picked up by dnsone-querylog within 15 s.
    background.add_task(runtime.apply_in_background)
    return {**after, "nodes": _export_state(db)}


def _role_names(db: Session) -> set[str]:
    from sqlalchemy import select
    return set(db.scalars(select(Role.name)))


@router.get("/sso")
def get_sso(actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    _need(oidc, "Single sign-on")
    return {"config": oidc.public(oidc.get(db)), "roles": sorted(_role_names(db))}


@router.put("/sso")
def set_sso(body: dict, actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    _need(oidc, "Single sign-on", write=True)
    before = oidc.public(oidc.get(db))
    try:
        after = oidc.public(oidc.store(db, body, _role_names(db)))
    except validation.ValidationError as exc:
        db.rollback()
        raise field_error(exc) from None
    except (TypeError, ValueError, AttributeError):
        db.rollback()
        raise ApiError(422, "The single sign-on settings are not in the expected form.") from None
    audit.record(db, actor.name, "settings.sso_updated", "settings", oidc.KEY, {"changes": {k: {"from": before[k], "to": after[k]}
                 for k in after if before.get(k) != after[k]}}, actor.ip)
    db.commit()
    return {"config": after, "roles": sorted(_role_names(db))}


@router.post("/sso/test")
def test_sso(actor: Actor = Depends(require("users.manage")), db: Session = Depends(get_db)) -> dict:
    _need(oidc, "Single sign-on")
    cfg = oidc.get(db)
    if not cfg["issuer"]:
        raise ApiError(422, "Enter and save the issuer first.", {"issuer": "Enter the provider's issuer URL."})
    try:
        return oidc.check(cfg)
    except oidc.OidcError as exc:
        raise ApiError(422, str(exc)) from None


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


@router.get("/update")
def software_update(refresh: bool = False, actor: Actor = Depends(require("system.manage"))) -> dict:
    """Settings → Overview → Software update: installed and latest versions, and the last install."""
    return updates.overview(refresh)


@router.post("/update")
def install_update(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    try:
        release = updates.request_install(actor.name)
    except updates.UpdateError as exc:
        raise ApiError(409, str(exc)) from None
    audit.record(db, actor.name, "settings.update_requested", "settings", "update",
                 {"from": __version__, "to": release["version"]}, actor.ip)
    db.commit()
    return {"message": f"Installing DNSOne {release['version']}: the console restarts in a minute or two."}


@router.post("/alerts/test")
def test_alerts(actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    results = alerts.send_test(db)
    audit.record(db, actor.name, "settings.alerts_tested", "settings", "alerts.config", {"results": results}, actor.ip)
    db.commit()
    return {"results": results}


@router.get("/backup")
def download_backup(
    sections: list[Section] = Query(["zones", "ad_blocking", "settings", "legal"]),
    actor: Actor = Depends(require("system.manage")),
    db: Session = Depends(get_db),
) -> JSONResponse:
    if actor.token is not None:
        # It holds every zone's DDNS and transfer secrets: a signed-in administrator, not a (read-only) app password.
        raise ApiError(403, "Download backups from the console: an app password cannot download them.")
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
        if "ad_blocking" in sections or "legal" in sections:
            rpz.RpzBuilder().build()
        runtime.apply()
    except Exception:  # noqa: BLE001 - the timers retry
        log.exception("follow-up after a restore failed")


@router.post("/restore")
def restore_backup(body: RestoreIn, background: BackgroundTasks, actor: Actor = Depends(require("system.manage")), db: Session = Depends(get_db)) -> dict:
    if "legal" in body.sections and not actor.can("legal.manage"):
        raise ApiError(403, "Restoring the court-ordered blocking list needs the legal.manage permission.")
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
