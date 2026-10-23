"""Node runtime files: what dnsdist and the Recursor's policy script read, generated from MySQL.

  dnsdist settings (DNSONE_DNSDIST_SETTINGS_FILE, a Lua table): client networks, NAT addresses,
      rate limits, public authoritative DNS on/off and the regex rules. dnsdist checks the file
      every 2 seconds (dnsdist.conf) and swaps its rules atomically.
  Recursor ACL (DNSONE_RECURSOR_ALLOW_FROM_FILE): the client networks; `rec_control reload-acls`.
  Recursor policy data (DNSONE_RECURSOR_POLICY_FILE, a Lua table, plus a .json twin that
      dnsone-querylog reads): which group each client is in, which RPZ each group uses, paused
      blocking and the regex rules; `rec_control reload-lua-script` (deploy/recursor/dnsone.lua).

apply() writes only what changed and reloads only that. The API calls it after a change, on the
node that served the request; `dnsone-ctl sync` (dnsone-sync.timer) brings every node up to date,
which is how changes reach the other nodes of a cluster (Phase 2).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
import zlib
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import rpz, validation
from .config import Settings, get_settings
from .db import NamedLock, new_session
from .models import ClientGroup, ClientGroupNetwork, RpzRule, Setting
from .system import atomic_write, run

log = logging.getLogger(__name__)

# PROXY protocol TLV type dnsdist uses to tell the Recursor which regex rules matched (0xE0-0xEF
# are free for applications).
REGEX_TLV = 0xE1
# "Pause until resumed".
FOREVER = 4102444800  # 2100-01-01
# Loopback always stays allowed: dnsdist's health checks and dig on the server itself.
LOOPBACK = ["127.0.0.0/8", "::1/128"]
DEFAULT_NETWORKS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]
SERVER_DEFAULTS = {"client_qps": 200, "client_burst": 400, "nat_qps": 5000, "nat_burst": 10000, "public_authoritative": True}


# --------------------------------------------------------------------------- Settings → DNS server

def _legacy_networks(path: Path) -> list[str] | None:
    """Networks from the Phase 1 client-networks.conf, if the file is there."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    out = []
    for line in lines:
        token = line.split("#", 1)[0].strip()
        if token:
            try:
                out.append(validation.network(token))
            except validation.ValidationError:
                log.warning("ignoring %r in %s", token, path)
    return [n for n in out if n not in LOOPBACK]


def server_settings(db: Session, settings: Settings | None = None) -> dict:
    s = settings or get_settings()
    row = db.get(Setting, "dns.server")
    if row is not None:
        return {**SERVER_DEFAULTS, "client_networks": [], "nat_addresses": [], **row.value}
    networks = _legacy_networks(s.legacy_client_networks_file)
    return {**SERVER_DEFAULTS, "client_networks": networks if networks is not None else DEFAULT_NETWORKS, "nat_addresses": []}


def _networks(values: list[str], field: str) -> list[str]:
    out: list[str] = []
    for i, raw in enumerate(values):
        net = validation.network(raw, f"{field}.{i}")
        if net not in out and net not in LOOPBACK:
            out.append(net)
    return out


def set_server_settings(db: Session, values: dict) -> dict:
    networks = _networks(values.get("client_networks") or [], "client_networks")
    if not networks:
        raise validation.ValidationError("client_networks", "List at least one customer network; without one nobody can use the resolver.")
    nat = _networks(values.get("nat_addresses") or [], "nat_addresses")
    out = {"client_networks": networks, "nat_addresses": nat, "public_authoritative": bool(values.get("public_authoritative", True))}
    for key in ("client_qps", "client_burst", "nat_qps", "nat_burst"):
        value = int(values.get(key) or SERVER_DEFAULTS[key])
        if not 1 <= value <= 1_000_000:
            raise validation.ValidationError(key, "Enter a number between 1 and 1,000,000.")
        out[key] = value
    for qps, burst in (("client_qps", "client_burst"), ("nat_qps", "nat_burst")):
        if out[burst] < out[qps]:
            raise validation.ValidationError(burst, "The burst must be at least the rate.")
    row = db.get(Setting, "dns.server")
    if row is None:
        db.add(Setting(name="dns.server", value=out))
    else:
        row.value = out
    return out


# --------------------------------------------------------------------------- pause

def get_pause(db: Session) -> dict:
    """{"all": epoch or None, "groups": {group id: epoch}}, expired entries removed."""
    row = db.get(Setting, "rpz.pause")
    value = dict(row.value) if row else {}
    now = time.time()
    everyone = value.get("all")
    return {
        "all": everyone if everyone and everyone > now else None,
        "groups": {int(k): v for k, v in (value.get("groups") or {}).items() if v and v > now},
    }


def set_pause(db: Session, group_id: int | None, minutes: int) -> dict:
    """minutes=0 pauses until resumed."""
    pause = get_pause(db)
    until = FOREVER if minutes == 0 else int(time.time()) + minutes * 60
    if group_id is None:
        pause["all"] = until
    else:
        pause["groups"][group_id] = until
    _store_pause(db, pause)
    return pause


def resume(db: Session, group_id: int | None) -> dict:
    """Resumes one group, or everyone (and every group) when group_id is None."""
    pause = get_pause(db)
    if group_id is None:
        pause = {"all": None, "groups": {}}
    else:
        pause["groups"].pop(group_id, None)
    _store_pause(db, pause)
    return pause


def _store_pause(db: Session, pause: dict) -> None:
    value = {"all": pause["all"], "groups": {str(k): v for k, v in pause["groups"].items()}}
    row = db.get(Setting, "rpz.pause", with_for_update=True)
    if row is None:
        db.add(Setting(name="rpz.pause", value=value))
    else:
        row.value = value


# --------------------------------------------------------------------------- rendering

def lua(value, indent: str = "") -> str:
    """A Python value as a Lua literal (dict keys: int or str; None values are left out)."""
    if value is None:
        return "nil"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
        return f'"{escaped}"'
    inner = indent + "  "
    if isinstance(value, (list, tuple)):
        if not value:
            return "{}"
        return "{\n" + "".join(f"{inner}{lua(v, inner)},\n" for v in value) + indent + "}"
    if isinstance(value, dict):
        items = [(k, v) for k, v in value.items() if v is not None]
        if not items:
            return "{}"
        keys = [f"[{k}]" if isinstance(k, int) else f"[{lua(str(k))}]" for k, _ in items]
        return "{\n" + "".join(f"{inner}{key} = {lua(v, inner)},\n" for key, (_, v) in zip(keys, items)) + indent + "}"
    raise TypeError(f"cannot write {type(value).__name__} as Lua")


def _serial(content: str) -> int:
    return zlib.crc32(content.encode())


def regex_rules(db: Session) -> list[RpzRule]:
    return list(db.scalars(select(RpzRule).where(RpzRule.match_type == "regex", RpzRule.enabled.is_(True)).order_by(RpzRule.id)))


def policy_data(db: Session, settings: Settings | None = None) -> dict:
    """What the Recursor's policy script and dnsone-querylog need to classify a query."""
    s = settings or get_settings()
    loaded = set(rpz.get_state(db, s).get("policies") or [])
    groups, files, default_group = {}, {}, None
    for g in db.scalars(select(ClientGroup).order_by(ClientGroup.id)):
        # The group's zones the Recursor has loaded: none until its first build, none with blocking off.
        policies = [name for name in rpz.group_policies(g) if g.blocking and name in loaded]
        groups[g.id] = {"name": g.name, "blocking": g.blocking, "policies": policies}
        for name in policies:
            files[name] = str(rpz.allow_file(g, s) if name == rpz.allow_policy_name(g) else rpz.group_file(g, s))
        if g.built_in:
            default_group = g.id
    networks, lengths4, lengths6 = {}, set(), set()
    for gid, cidr in db.execute(select(ClientGroupNetwork.group_id, ClientGroupNetwork.network)):
        net = ipaddress.ip_network(cidr)
        networks[f"{net.network_address}/{net.prefixlen}"] = gid
        (lengths4 if net.version == 4 else lengths6).add(net.prefixlen)
    pause = get_pause(db)
    policy = rpz.get_policy(db)
    data = {
        "default_group": default_group,
        "groups": groups,
        "networks": networks,
        "lengths4": sorted(lengths4, reverse=True),
        "lengths6": sorted(lengths6, reverse=True),
        "policies": sorted(loaded),
        # For dnsone-querylog, which classifies against the same files.
        "files": files,
        "pause": {"all": pause["all"], "groups": pause["groups"]},
        "regex": {r.id: {"pattern": r.pattern, "action": r.action, "group": r.group_id} for r in regex_rules(db)},
        "answer": {"action": policy["action"], "target": policy["walled_garden_target"]},
    }
    data["serial"] = _serial(json.dumps(data, sort_keys=True, default=str))
    return data


def render_policy_lua(data: dict) -> str:
    return "-- Generated by DNSOne (runtime.py) for deploy/recursor/dnsone.lua. Do not edit.\nreturn " + lua(data) + "\n"


def render_dnsdist(server: dict, regex: list[RpzRule]) -> str:
    body = {
        "client_networks": LOOPBACK + server["client_networks"],
        "nat_addresses": server["nat_addresses"],
        "client_qps": server["client_qps"],
        "client_burst": server["client_burst"],
        "nat_qps": server["nat_qps"],
        "nat_burst": server["nat_burst"],
        "public_authoritative": server["public_authoritative"],
        "regex_tlv": REGEX_TLV,
        "regex": [{"id": r.id, "re": r.pattern} for r in regex],
    }
    body["serial"] = _serial(json.dumps(body, sort_keys=True))
    return "-- Generated by DNSOne (runtime.py) for dnsdist.conf. Do not edit: Settings → DNS server.\nreturn " + lua(body) + "\n"


def render_allow_from(server: dict) -> str:
    return "# Generated by DNSOne: Settings → DNS server, client networks. Do not edit.\n" + "".join(
        f"{n}\n" for n in LOOPBACK + server["client_networks"])


# --------------------------------------------------------------------------- applying

def _write_if_changed(path: Path, content: str) -> bool:
    try:
        if path.read_text(encoding="utf-8") == content:
            return False
    except OSError:
        pass
    atomic_write(path, content, 0o644)
    return True


def apply(settings: Settings | None = None) -> list[str]:
    """Writes this node's runtime files from MySQL and reloads what changed. Returns what it did."""
    s = settings or get_settings()
    messages: list[str] = []
    with NamedLock(f"dnsone:runtime:{s.node_name}", timeout=60):
        db = new_session()
        try:
            server = server_settings(db, s)
            data = policy_data(db, s)
            regex = regex_rules(db)

            if _write_if_changed(s.dnsdist_settings_file, render_dnsdist(server, regex)):
                messages.append("dnsdist settings written (dnsdist applies them within 2 s)")

            if _write_if_changed(s.recursor_allow_from_file, render_allow_from(server)):
                code, out = run([*s.rec_control, "reload-acls"], timeout=s.command_timeout)
                messages.append("Recursor ACL reloaded" if code == 0 else f"warning: rec_control reload-acls failed: {out}")

            # The JSON twin first: dnsone-querylog classifies with it.
            _write_if_changed(s.recursor_policy_file.with_suffix(".json"), json.dumps(data, sort_keys=True))
            if _write_if_changed(s.recursor_policy_file, render_policy_lua(data)):
                # No cache wipe needed: group, pause and regex verdict are part of the packet cache key.
                code, out = run([*s.rec_control, "reload-lua-script"], timeout=s.command_timeout)
                messages.append("Recursor policy script reloaded" if code == 0 else f"warning: rec_control reload-lua-script failed: {out}")
        finally:
            db.close()
    for m in messages:
        log.info("runtime: %s", m)
    return messages


def apply_in_background() -> None:
    try:
        apply()
    except Exception:  # noqa: BLE001 - logged; dnsone-sync.timer applies again
        log.exception("applying runtime files failed")
