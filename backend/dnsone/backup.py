"""Settings → Backup ("Teleporter"): settings, lists and rules (and optionally zones) as one JSON file.

Sections:
  zones        every zone with its records, dynamic DNS keys and transfer settings, and the zone templates
  ad_blocking  blocklists and allowlists, client groups with their networks, rules, Safe Search, DNS64, the block policy
  settings     Settings → DNS server (with the resolver's ECS and serve-stale), Privacy, Query log export,
               and Protection (thresholds and lasting blocks)
  legal        the court-ordered blocking list (active and lifted entries) and the notice page

Operators, sessions, app passwords, the audit log, the query log and the firewall are never included
(firewall rules belong to one server's addresses: restored elsewhere they could lock it out). A restore
replaces each chosen section completely, in one transaction, after validating every item the way
the API does; items that fail are skipped and reported. Afterwards zones are republished, lists
downloaded again and the RPZ rebuilt in the background.
"""

from __future__ import annotations

from sqlalchemy import delete, insert, select, update
from sqlalchemy.orm import Session

from datetime import date

from . import __version__, ddns, privacy, rpz, runtime, templates, validation
from .edition import pro

legal, logexport, protection, transfers = pro("legal"), pro("logexport"), pro("protection"), pro("transfers")
from .config import get_settings
from .models import (Blocklist, ClientGroup, ClientGroupNetwork, DdnsKey, LegalBlock, ProtectionBlock, Record, RpzRule, Setting, Zone, ZoneTemplate,
                     ZoneTransfer, user_zones)
from .system import utcnow

FORMAT = 1
# The court-ordered blocking list is a section of its own, in the edition that has it (Pro).
SECTIONS = ("zones", "ad_blocking", "settings") + (("legal",) if legal is not None else ())
SOA_FIELDS = ("soa_refresh", "soa_retry", "soa_expire", "soa_minimum")


class RestoreError(ValueError):
    pass


def export(db: Session, sections: list[str]) -> dict:
    out: dict = {
        "dnsone_backup": FORMAT, "version": __version__, "node": get_settings().node_name,
        "created_at": utcnow().isoformat(timespec="seconds") + "Z", "sections": [s for s in SECTIONS if s in sections],
    }
    if "zones" in sections:
        out["zones"] = []
        for z in db.scalars(select(Zone).order_by(Zone.name)):
            records = db.scalars(select(Record).where(Record.zone_id == z.id).order_by(Record.name, Record.type, Record.id))
            out["zones"].append({
                "name": z.name, "description": z.description, "status": z.status, "dnssec": z.dnssec, "default_ttl": z.default_ttl,
                "soa_mname": z.soa_mname, "soa_rname": z.soa_rname, **{f: getattr(z, f) for f in SOA_FIELDS},
                "records": [{"name": r.name, "type": r.type, "value": r.value, "ttl": r.ttl, "priority": r.priority,
                             "disabled": r.disabled, "comment": r.comment} for r in records],
                "ddns_keys": [{"name": k.name, "algorithm": k.algorithm, "secret": k.secret, "names": k.names, "types": k.types,
                               "enabled": k.enabled, "comment": k.comment} for k in db.scalars(select(DdnsKey).where(DdnsKey.zone_id == z.id))],
                "transfers": [{"address": t.address, "notify": t.notify, "notify_port": t.notify_port, "comment": t.comment}
                              for t in (transfers.entries(db, z.id) if transfers is not None else [])],
                "transfer_key": {"algorithm": z.xfr_key_algorithm, "secret": z.xfr_key_secret} if z.xfr_key_name else None,
            })
        out["templates"] = [{k: v for k, v in templates.out(t).items() if k not in ("id", "updated_at", "created_by")}
                            for t in db.scalars(select(ZoneTemplate).order_by(ZoneTemplate.name))]
    if "ad_blocking" in sections:
        out["blocklists"] = [{"name": b.name, "url": b.url, "format": b.format, "kind": b.kind, "enabled": b.enabled}
                             for b in db.scalars(select(Blocklist).order_by(Blocklist.name))]
        out["groups"] = [{"name": g.name, "description": g.description, "blocking": g.blocking, "built_in": g.built_in,
                          "safe_search": g.safe_search, "youtube": g.youtube, "dns64": g.dns64,
                          "networks": [{"network": n.network, "comment": n.comment} for n in g.networks],
                          "blocklists": sorted(b.name for b in g.blocklists)}
                         for g in db.scalars(select(ClientGroup).order_by(ClientGroup.built_in.desc(), ClientGroup.name))]
        names = dict(db.execute(select(ClientGroup.id, ClientGroup.name)).all())
        out["rules"] = [{"pattern": r.pattern, "match_type": r.match_type, "action": r.action, "target": r.target,
                         "group": names.get(r.group_id) if r.group_id else None, "enabled": r.enabled, "comment": r.comment, "source": r.source}
                        for r in db.scalars(select(RpzRule).order_by(RpzRule.pattern))]
        out["rpz_policy"] = rpz.get_policy(db)
    if "settings" in sections:
        stored = db.get(Setting, "dns.server")
        out["dns_server"] = stored.value if stored else None
        out["privacy"] = privacy.get(db)
        if logexport is not None:
            out["export"] = logexport.get(db)
        out["resolver"] = runtime.resolver_settings(db)
        if protection is not None:
            out["protection"] = protection.get_config(db)
            out["protection_blocks"] = [{"kind": b.kind, "value": b.value, "reason": b.reason}
                                        for b in protection.active_blocks(db) if b.expires_at is None]
    if "legal" in sections and legal is not None:
        out["legal_blocks"] = [{"pattern": b.pattern, "authority": b.authority, "reference": b.reference,
                                "ordered_on": b.ordered_on.isoformat() if b.ordered_on else None, "notes": b.notes, "active": b.active,
                                "created_by": b.created_by, "created_at": b.created_at.isoformat() if b.created_at else None,
                                "lifted_at": b.lifted_at.isoformat() if b.lifted_at else None, "lifted_by": b.lifted_by, "lift_reason": b.lift_reason}
                               for b in db.scalars(select(LegalBlock).order_by(LegalBlock.id))]
        out["legal_page"] = legal.get_page(db)
    return out


def _check(data: dict, sections: list[str]) -> None:
    if not isinstance(data, dict) or data.get("dnsone_backup") != FORMAT:
        raise RestoreError("This is not a DNSOne backup file (or it is from a newer, incompatible version).")
    missing = [s for s in sections if s not in (data.get("sections") or [])]
    if missing:
        raise RestoreError(f"The backup does not contain: {', '.join(missing)}.")


def _restore_zones(db: Session, data: dict, report: dict) -> None:
    # Customers keep the zones they had, by name (deleting the zones drops user_zones with them).
    owners: dict[str, list[int]] = {}
    for user_id, zone_name in db.execute(select(user_zones.c.user_id, Zone.name).join(Zone, Zone.id == user_zones.c.zone_id)):
        owners.setdefault(zone_name, []).append(user_id)
    db.execute(delete(Zone))
    for z in data.get("zones") or []:
        try:
            name = validation.zone_name(str(z["name"]))
            ttl = validation.ttl(int(z["default_ttl"]), "default_ttl", allow_none=False)
            soa = {}
            for field in SOA_FIELDS:
                low, high = validation.SOA_BOUNDS[field]
                value = int(z[field])
                if not low <= value <= high:
                    raise validation.ValidationError(field, f"{field} out of range")
                soa[field] = value
            zone = Zone(name=name, description=str(z.get("description") or "")[:255], status="disabled" if z.get("status") == "disabled" else "active",
                        # The signing keys stay with BIND (key directory), not in the backup: restored on
                        # another server, a signed zone gets new keys, and its DS at the parent must change.
                        dnssec=z.get("dnssec") if z.get("dnssec") in ("on", "insecure") else "off",
                        default_ttl=ttl, soa_mname=validation.absolute_name(str(z["soa_mname"]), name, "soa_mname"),
                        soa_rname=validation.mailbox(str(z["soa_rname"]), name),
                        revision=1, published_revision=0, publish_state="pending", **soa)
        except (KeyError, TypeError, ValueError, validation.ValidationError) as exc:
            report["skipped"].append(f"zone {z.get('name', '?')}: {getattr(exc, 'message', exc)}")
            continue
        db.add(zone)
        db.flush()
        if owners.get(name):
            db.execute(insert(user_zones), [{"user_id": u, "zone_id": zone.id} for u in owners[name]])
        seen = set()
        for r in z.get("records") or []:
            try:
                rname, rtype, value, priority = validation.record(name, str(r["name"]), str(r["type"]), str(r["value"]), r.get("priority"))
                rttl = validation.ttl(r.get("ttl"))
            except (KeyError, TypeError, validation.ValidationError) as exc:
                report["skipped"].append(f"record {r.get('name', '?')} {r.get('type', '?')} in {name}: {getattr(exc, 'message', exc)}")
                continue
            key = (rname, rtype, priority, value)
            if key in seen:
                continue
            seen.add(key)
            db.add(Record(zone_id=zone.id, name=rname, type=rtype, value=value, ttl=rttl, priority=priority,
                          disabled=bool(r.get("disabled")), comment=str(r.get("comment") or "")[:255]))
        for k in z.get("ddns_keys") or []:
            try:
                key = DdnsKey(zone_id=zone.id, name=ddns.key_name(str(k["name"]), name), secret=ddns.clean_secret(str(k["secret"])),
                              algorithm=k.get("algorithm") if k.get("algorithm") in ddns.ALGORITHMS else "hmac-sha256",
                              names=ddns.clean_names(list(k.get("names") or []), name), types=ddns.clean_types(list(k.get("types") or [])),
                              enabled=bool(k.get("enabled", True)), comment=str(k.get("comment") or "")[:255], created_by="restore")
            except (KeyError, TypeError, validation.ValidationError) as exc:
                report["skipped"].append(f"dynamic DNS key {k.get('name', '?')} in {name}: {getattr(exc, 'message', exc)}")
                continue
            db.add(key)
        if transfers is None and (z.get("transfers") or z.get("transfer_key")):
            report["skipped"].append(f"zone transfers of {name}: they need DNSOne Pro")
        for t in (z.get("transfers") or [])[: transfers.MAX_PER_ZONE] if transfers is not None else []:
            try:
                address = transfers.clean_address(str(t["address"]))
                port = int(t.get("notify_port") or 53)
                if not 1 <= port <= 65535:
                    raise validation.ValidationError("notify_port", "out of range")
            except (KeyError, TypeError, ValueError, validation.ValidationError) as exc:
                report["skipped"].append(f"secondary {t.get('address', '?')} of {name}: {getattr(exc, 'message', exc)}")
                continue
            db.add(ZoneTransfer(zone_id=zone.id, address=address, notify=bool(t.get("notify", True)) and transfers.is_single(address),
                                notify_port=port, comment=str(t.get("comment") or "")[:255], created_by="restore"))
        key_data = z.get("transfer_key")
        if key_data and transfers is not None:
            try:
                transfers.set_key(zone, True, str(key_data.get("algorithm") or "hmac-sha256"), str(key_data.get("secret") or ""))
            except (TypeError, AttributeError, validation.ValidationError) as exc:
                report["skipped"].append(f"transfer key of {name}: {getattr(exc, 'message', exc)}")
        db.flush()
        report["zones"] += 1
    db.execute(delete(ZoneTemplate))
    for t in data.get("templates") or []:
        try:
            cleaned = templates.clean(t)
            if not cleaned["name"]:
                raise validation.ValidationError("name", "no name")
        except (TypeError, ValueError, AttributeError, validation.ValidationError) as exc:
            report["skipped"].append(f"template {t.get('name', '?')}: {getattr(exc, 'message', exc)}")
            continue
        db.add(ZoneTemplate(**cleaned, created_by="restore"))
        db.flush()


def _restore_ad_blocking(db: Session, data: dict, report: dict) -> None:
    db.execute(delete(RpzRule))
    db.execute(delete(ClientGroupNetwork))
    db.execute(delete(Blocklist))
    db.execute(delete(ClientGroup).where(ClientGroup.built_in.is_(False)))
    db.flush()
    default = db.scalar(select(ClientGroup).where(ClientGroup.built_in.is_(True)))
    lists: dict[str, Blocklist] = {}
    for b in data.get("blocklists") or []:
        try:
            url = str(b["url"]).strip()
            if not url.startswith(("http://", "https://")):
                raise validation.ValidationError("url", "not an http(s) URL")
            bl = Blocklist(name=str(b["name"])[:128], url=url, format=b.get("format") if b.get("format") in ("auto", "hosts", "domains", "adblock") else "auto",
                           kind="allow" if b.get("kind") == "allow" else "block", enabled=bool(b.get("enabled", True)))
        except (KeyError, TypeError, validation.ValidationError) as exc:
            report["skipped"].append(f"blocklist {b.get('name', '?')}: {getattr(exc, 'message', exc)}")
            continue
        if bl.name in lists:
            continue
        db.add(bl)
        lists[bl.name] = bl
        report["blocklists"] += 1
    db.flush()
    groups: dict[str, ClientGroup] = {}
    taken: set[str] = set()
    for g in data.get("groups") or []:
        if g.get("built_in"):
            group = default
            group.description = str(g.get("description") or group.description)[:255]
        else:
            name = str(g.get("name") or "").strip()[:64]
            if not name or name in groups or name == default.name:
                report["skipped"].append(f"group {name or '?'}: missing or duplicate name")
                continue
            group = ClientGroup(name=name, description=str(g.get("description") or "")[:255])
            db.add(group)
            report["groups"] += 1
        group.blocking = bool(g.get("blocking", True))
        group.safe_search = bool(g.get("safe_search", False))
        group.youtube = g.get("youtube") if g.get("youtube") in ("off", "moderate", "strict") else "off"
        group.dns64 = bool(g.get("dns64", False))
        group.blocklists = [lists[n] for n in g.get("blocklists") or [] if n in lists]
        groups[group.name] = group
        db.flush()
        if group.built_in:
            continue
        for n in g.get("networks") or []:
            try:
                network = validation.network(str(n["network"]))
            except (KeyError, TypeError, validation.ValidationError) as exc:
                report["skipped"].append(f"network in {group.name}: {getattr(exc, 'message', exc)}")
                continue
            if network in taken:
                report["skipped"].append(f"network {network} in {group.name}: already in another group")
                continue
            taken.add(network)
            db.add(ClientGroupNetwork(group_id=group.id, network=network, comment=str(n.get("comment") or "")[:255]))
            report["networks"] += 1
    seen = set()
    for r in data.get("rules") or []:
        try:
            match_type = "regex" if r.get("match_type") == "regex" else "exact"
            action = r["action"]
            if action not in ("block", "allow", "nxdomain", "nodata", "redirect") or (match_type == "regex" and action not in ("block", "allow")):
                raise validation.ValidationError("action", f"unknown action {action}")
            pattern = validation.regex_pattern(r["pattern"]) if match_type == "regex" else validation.rpz_pattern(r["pattern"])
            target = validation.walled_garden_target(r.get("target") or "", "target") if action == "redirect" else None
            group = groups.get(r["group"]) if r.get("group") else None
            if r.get("group") and group is None:
                raise validation.ValidationError("group", f"group {r['group']} is not in the backup")
        except (KeyError, TypeError, validation.ValidationError) as exc:
            report["skipped"].append(f"rule {r.get('pattern', '?')}: {getattr(exc, 'message', exc)}")
            continue
        key = (pattern, group.id if group else 0)
        if key in seen:
            continue
        seen.add(key)
        db.add(RpzRule(pattern=pattern, match_type=match_type, action=action, target=target, group_id=group.id if group else None,
                       enabled=bool(r.get("enabled", True)), comment=str(r.get("comment") or "")[:255], source=str(r.get("source") or "restore")[:64],
                       created_by="restore"))
        report["rules"] += 1
    policy = data.get("rpz_policy") or {}
    try:
        rpz.set_policy(db, policy.get("action", "nxdomain"), policy.get("walled_garden_target", ""), bool(policy.get("block_subdomains", True)))
    except validation.ValidationError as exc:
        report["skipped"].append(f"block policy: {exc.message}")
    rpz.mark_changed(db)


def _restore_settings(db: Session, data: dict, report: dict) -> None:
    if data.get("dns_server"):
        try:
            runtime.set_server_settings(db, data["dns_server"])
            report["settings"].append("DNS server")
        except (TypeError, ValueError, validation.ValidationError) as exc:
            report["skipped"].append(f"DNS server settings: {getattr(exc, 'message', exc)}")
    if data.get("privacy"):
        p = data["privacy"]
        try:
            retention = min(int(p.get("retention_hours") or 24), get_settings().querylog_retention_hours)
            privacy.store(db, int(p.get("level", 0)), retention)
            report["settings"].append("Privacy")
        except (TypeError, ValueError, validation.ValidationError) as exc:
            report["skipped"].append(f"privacy settings: {getattr(exc, 'message', exc)}")
    if data.get("export") and logexport is None:
        report["skipped"].append("query log export settings: they need DNSOne Pro")
    elif data.get("export"):
        try:
            logexport.store(db, data["export"])
            report["settings"].append("Query log export")
        except (TypeError, ValueError, validation.ValidationError) as exc:
            report["skipped"].append(f"query log export settings: {getattr(exc, 'message', exc)}")
    if data.get("resolver"):
        try:
            runtime.set_resolver_settings(db, data["resolver"])
            report["settings"].append("Resolver")
        except (TypeError, ValueError, AttributeError, validation.ValidationError) as exc:
            report["skipped"].append(f"resolver settings: {getattr(exc, 'message', exc)}")
    if (data.get("protection") or data.get("protection_blocks")) and protection is None:
        report["skipped"].append("attack protection settings and blocks: they need DNSOne Pro")
        return
    if data.get("protection"):
        try:
            protection.store_config(db, data["protection"])
            report["settings"].append("Protection")
        except (TypeError, ValueError, AttributeError, validation.ValidationError) as exc:
            report["skipped"].append(f"protection thresholds: {getattr(exc, 'message', exc)}")
    if "protection_blocks" in data:
        db.execute(delete(ProtectionBlock).where(ProtectionBlock.expires_at.is_(None)))
        for b in data.get("protection_blocks") or []:
            try:
                kind = str(b["kind"])
                value = protection.clean_block(kind, str(b["value"]))
            except (KeyError, TypeError, validation.ValidationError) as exc:
                report["skipped"].append(f"protection block {b.get('value', '?')}: {getattr(exc, 'message', exc)}")
                continue
            db.execute(delete(ProtectionBlock).where(ProtectionBlock.kind == kind, ProtectionBlock.value == value))
            db.add(ProtectionBlock(kind=kind, value=value, reason=str(b.get("reason") or "")[:255], created_by="restore"))


def _restore_legal(db: Session, data: dict, report: dict) -> None:
    """Adds the backup's entries that are missing here; nothing is lifted or deleted (the list keeps its history)."""
    have = {(b.pattern, b.reference, b.active) for b in db.scalars(select(LegalBlock))}
    active = {b.pattern for b in db.scalars(select(LegalBlock).where(LegalBlock.active.is_(True)))}
    for b in data.get("legal_blocks") or []:
        try:
            pattern = validation.rpz_pattern(str(b["pattern"]))
            authority, reference = str(b["authority"]).strip()[:128], str(b["reference"]).strip()[:128]
            if not authority or not reference:
                raise validation.ValidationError("reference", "missing authority or reference")
            ordered = date.fromisoformat(b["ordered_on"]) if b.get("ordered_on") else None
        except (KeyError, TypeError, ValueError, validation.ValidationError) as exc:
            report["skipped"].append(f"court order entry {b.get('pattern', '?')}: {getattr(exc, 'message', exc)}")
            continue
        is_active = bool(b.get("active", True))
        if (pattern, reference, is_active) in have or (is_active and pattern in active):
            continue
        db.add(LegalBlock(pattern=pattern, authority=authority, reference=reference, ordered_on=ordered, notes=str(b.get("notes") or "")[:1000],
                          active=is_active, created_by=str(b.get("created_by") or "restore")[:64],
                          lifted_by=None if is_active else str(b.get("lifted_by") or "restore")[:64],
                          lifted_at=None if is_active else utcnow(), lift_reason=None if is_active else str(b.get("lift_reason") or "")[:255]))
        if is_active:
            active.add(pattern)
        report["legal"] += 1
    if data.get("legal_page"):
        try:
            legal.set_page(db, data["legal_page"])
        except (TypeError, validation.ValidationError) as exc:
            report["skipped"].append(f"legal notice page: {getattr(exc, 'message', exc)}")
    rpz.mark_changed(db)


def restore(db: Session, data: dict, sections: list[str]) -> dict:
    """Replaces the chosen sections; the caller commits and starts the follow-up jobs."""
    sections = [s for s in SECTIONS if s in sections]
    if not sections:
        raise RestoreError("Choose at least one part of the backup to restore.")
    _check(data, sections)
    report: dict = {"sections": sections, "zones": 0, "blocklists": 0, "groups": 0, "networks": 0, "rules": 0, "legal": 0, "settings": [], "skipped": []}
    if "zones" in sections:
        _restore_zones(db, data, report)
    if "ad_blocking" in sections:
        _restore_ad_blocking(db, data, report)
    if "settings" in sections:
        _restore_settings(db, data, report)
    if "legal" in sections:
        _restore_legal(db, data, report)
    if "zones" in sections:
        db.execute(update(Zone).values(publish_state="pending"))
    return report
