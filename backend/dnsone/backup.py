"""Settings → Backup ("Teleporter"): settings, lists and rules (and optionally zones) as one JSON file.

Sections:
  zones        every zone with its records
  ad_blocking  blocklists and allowlists, client groups with their networks, rules, the block policy
  settings     Settings → DNS server and Settings → Privacy

Operators, sessions, app passwords, the audit log and the query log are never included. A restore
replaces each chosen section completely, in one transaction, after validating every item the way
the API does; items that fail are skipped and reported. Afterwards zones are republished, lists
downloaded again and the RPZ rebuilt in the background.
"""

from __future__ import annotations

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from . import __version__, privacy, rpz, runtime, validation
from .config import get_settings
from .models import Blocklist, ClientGroup, ClientGroupNetwork, Record, RpzRule, Setting, Zone
from .system import utcnow

FORMAT = 1
SECTIONS = ("zones", "ad_blocking", "settings")
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
            })
    if "ad_blocking" in sections:
        out["blocklists"] = [{"name": b.name, "url": b.url, "format": b.format, "kind": b.kind, "enabled": b.enabled}
                             for b in db.scalars(select(Blocklist).order_by(Blocklist.name))]
        out["groups"] = [{"name": g.name, "description": g.description, "blocking": g.blocking, "built_in": g.built_in,
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
    return out


def _check(data: dict, sections: list[str]) -> None:
    if not isinstance(data, dict) or data.get("dnsone_backup") != FORMAT:
        raise RestoreError("This is not a DNSOne backup file (or it is from a newer, incompatible version).")
    missing = [s for s in sections if s not in (data.get("sections") or [])]
    if missing:
        raise RestoreError(f"The backup does not contain: {', '.join(missing)}.")


def _restore_zones(db: Session, data: dict, report: dict) -> None:
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
        report["zones"] += 1


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


def restore(db: Session, data: dict, sections: list[str]) -> dict:
    """Replaces the chosen sections; the caller commits and starts the follow-up jobs."""
    sections = [s for s in SECTIONS if s in sections]
    if not sections:
        raise RestoreError("Choose at least one part of the backup to restore.")
    _check(data, sections)
    report: dict = {"sections": sections, "zones": 0, "blocklists": 0, "groups": 0, "networks": 0, "rules": 0, "settings": [], "skipped": []}
    if "zones" in sections:
        _restore_zones(db, data, report)
    if "ad_blocking" in sections:
        _restore_ad_blocking(db, data, report)
    if "settings" in sections:
        _restore_settings(db, data, report)
    if "zones" in sections:
        db.execute(update(Zone).values(publish_state="pending"))
    return report
