"""The server's firewall (Settings → Firewall): nftables rules managed from the console.

DNSOne owns one nftables table, `inet dnsone`, with an input chain that drops what it does not allow:

  always      established connections, loopback, the ICMP that IPv4 and IPv6 need (path MTU, neighbour
              discovery, echo with a rate limit), and SSH and the console (22, 80, 443) from the
              management networks; nothing below can take these away
  rules       the operator's rules, in order: accept, drop or reject by source, protocol and ports
              (temporary ones, e.g. a block from the Protection page, expire by themselves)
  services    DNS (53 UDP and TCP) from anywhere, DNS over TLS (853) and DNS over HTTPS (443) if on;
              zone transfers to the cluster's BIND secondaries (5301 from their addresses)
  policy      everything else is dropped

Rule edits are a draft. Apply stores a snapshot of the configuration and rules (setting firewall.active)
and leaves a request for dnsone-firewall (root, through dnsone-firewall.path): it renders the snapshot
itself, checks it with `nft -c`, applies it in one transaction and waits for the console to confirm
it can still reach the server. Without a confirmation within CONFIRM_SECONDS it puts the previous
rules back (and the previous snapshot in MySQL). The other nodes of a cluster load the snapshot from
MySQL with `dnsone-ctl sync`, without the wait. At boot, dnsone-firewall.service loads the last
confirmed rules before the network comes up.

The API never writes nftables rules: dnsone-firewall reads the snapshot from MySQL and renders it from
validated fields only (addresses, port numbers, fixed words), so nothing in the database is ever passed
to nft as text.

    python -m dnsone.firewall apply      what dnsone-firewall-apply.service runs (root)
    python -m dnsone.firewall boot       what dnsone-firewall.service runs at boot (root)
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import validation
from .config import Settings, get_settings
from .models import FirewallRule, Setting
from .system import utcnow

log = logging.getLogger(__name__)

TABLE = "dnsone"
CONFIG_KEY = "firewall.config"
ACTIVE_KEY = "firewall.active"
PREVIOUS_KEY = "firewall.previous"
REQUEST = "request"
CONFIRM = "confirm"
CONFIRM_SECONDS = 60
NFT = "/usr/sbin/nft"
MAX_RULES = 500
ACTIONS = ("accept", "drop", "reject")
PROTOCOLS = ("tcp", "udp", "tcp+udp", "icmp", "any")
CONFIG_DEFAULTS = {"enabled": False, "management_networks": [], "dns": True, "dot": False, "doh": False}
MANAGEMENT_PORTS = (22, 80, 443)
SECONDARY_PORT = 5301


class FirewallError(Exception):
    pass


# --------------------------------------------------------------------------- configuration and rules


def get_config(db: Session) -> dict:
    row = db.get(Setting, CONFIG_KEY)
    return {**CONFIG_DEFAULTS, **(row.value if row else {})}


def store_config(db: Session, values: dict) -> dict:
    nets: list[str] = []
    for i, raw in enumerate(values.get("management_networks") or []):
        if not str(raw).strip():
            continue
        net = validation.network(str(raw), f"management_networks.{i}")
        if ipaddress.ip_network(net).prefixlen == 0:
            raise validation.ValidationError(f"management_networks.{i}", "List your management networks; the whole internet is not one.")
        if net not in nets:
            nets.append(net)
    out = {"enabled": bool(values.get("enabled")), "management_networks": nets,
           "dns": bool(values.get("dns", True)), "dot": bool(values.get("dot")), "doh": bool(values.get("doh"))}
    if out["enabled"] and not nets:
        raise validation.ValidationError("management_networks", "List at least one management network: SSH and the console stay open to it.")
    row = db.get(Setting, CONFIG_KEY)
    if row is None:
        db.add(Setting(name=CONFIG_KEY, value=out))
    else:
        row.value = out
    return out


def clean_ports(raw: str, protocol: str) -> str:
    """'22', '80,443', '1000-2000' in canonical form; '' (every port), and always '' for icmp and any."""
    value = raw.replace(" ", "")
    if protocol in ("icmp", "any") or not value:
        return ""
    parts = []
    for part in value.split(","):
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", part)
        if not m:
            raise validation.ValidationError("ports", "Ports are numbers, ranges and commas: 22, 80,443 or 1000-2000.")
        low, high = int(m.group(1)), int(m.group(2) or m.group(1))
        if not 1 <= low <= high <= 65535:
            raise validation.ValidationError("ports", "Ports go from 1 to 65535; a range goes from low to high.")
        parts.append(str(low) if low == high else f"{low}-{high}")
    if len(parts) > 32:
        raise validation.ValidationError("ports", "At most 32 ports or ranges in one rule.")
    return ",".join(parts)


def clean_rule(values: dict) -> dict:
    action = str(values.get("action") or "")
    if action not in ACTIONS:
        raise validation.ValidationError("action", "Choose accept, drop or reject.")
    protocol = str(values.get("protocol") or "tcp")
    if protocol not in PROTOCOLS:
        raise validation.ValidationError("protocol", "Choose tcp, udp, tcp+udp, icmp or any.")
    source = str(values.get("source") or "").strip()
    if source:
        source = validation.network(source, "source")
        if ipaddress.ip_network(source).prefixlen == 0:
            source = ""
    ports = clean_ports(str(values.get("ports") or ""), protocol)
    if not source and not ports and action != "accept":
        raise validation.ValidationError("source", "A rule that drops everything from everywhere would cut the server off; give a source or ports.")
    return {"action": action, "protocol": protocol, "source": source, "ports": ports}


def rules(db: Session) -> list[FirewallRule]:
    return list(db.scalars(select(FirewallRule).order_by(FirewallRule.position, FirewallRule.id)))


def rule_dict(r: FirewallRule) -> dict:
    return {"id": r.id, "action": r.action, "protocol": r.protocol, "source": r.source, "ports": r.ports, "enabled": r.enabled,
            "expires_at": r.expires_at.isoformat(timespec="seconds") if r.expires_at else None}


def secondaries(db: Session) -> list[str]:
    row = db.get(Setting, "cluster.secondaries")
    return [str(s["address"]) for s in (row.value.get("servers", []) if row else [])]


def draft(db: Session) -> dict:
    """The configuration and rules as they are now (what Apply would put live)."""
    return {"config": get_config(db), "rules": [rule_dict(r) for r in rules(db)], "secondaries": secondaries(db)}


def active(db: Session) -> dict | None:
    row = db.get(Setting, ACTIVE_KEY)
    return dict(row.value) if row else None


# --------------------------------------------------------------------------- rendering (also run as root)


def _net(raw: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(raw, strict=False)


def _ports(raw: str) -> str:
    parts = []
    for part in raw.split(","):
        if not part:
            continue
        low, _, high = part.partition("-")
        low_i, high_i = int(low), int(high or low)
        if not 1 <= low_i <= high_i <= 65535:
            raise FirewallError(f"bad port {part!r}")
        parts.append(str(low_i) if low_i == high_i else f"{low_i}-{high_i}")
    return "{ " + ", ".join(parts) + " }" if len(parts) > 1 else parts[0] if parts else ""


def _rule_lines(rule: dict, now: datetime) -> list[str]:
    if not rule.get("enabled", True):
        return []
    if rule.get("expires_at") and datetime.fromisoformat(rule["expires_at"]) <= now:
        return []
    action, protocol = rule["action"], rule["protocol"]
    if action not in ACTIONS or protocol not in PROTOCOLS:
        raise FirewallError(f"rule {rule.get('id')}: bad action or protocol")
    families = ["ip", "ip6"]
    match = ""
    if rule.get("source"):
        net = _net(rule["source"])
        families = ["ip" if net.version == 4 else "ip6"]
        match = f"{families[0]} saddr {net} "
    ports = _ports(clean_ports(rule.get("ports") or "", protocol)) if protocol in ("tcp", "udp", "tcp+udp") else ""
    tag = f'comment "rule {int(rule["id"])}"'
    if protocol == "tcp":
        return [f"{match}tcp dport {ports} {action} {tag}" if ports else f"{match}meta l4proto tcp {action} {tag}"]
    if protocol == "udp":
        return [f"{match}udp dport {ports} {action} {tag}" if ports else f"{match}meta l4proto udp {action} {tag}"]
    if protocol == "tcp+udp":
        return [f"{match}meta l4proto {{ tcp, udp }} th dport {ports} {action} {tag}" if ports else f"{match}meta l4proto {{ tcp, udp }} {action} {tag}"]
    if protocol == "icmp":
        return [f"{match}meta l4proto {'icmp' if f == 'ip' else 'ipv6-icmp'} {action} {tag}" for f in families]
    return [f"{match}{action} {tag}" if match else f"meta nfproto {{ ipv4, ipv6 }} {action} {tag}"]


def render(snapshot: dict | None, now: datetime | None = None) -> str:
    """The nft script for a snapshot ({config, rules, secondaries}); None or disabled: the table removed."""
    now = now or utcnow()
    head = ["# Generated by DNSOne (firewall.py): Settings → Firewall. Do not edit; Apply replaces it.",
            f"table inet {TABLE}", f"delete table inet {TABLE}"]
    cfg = {**CONFIG_DEFAULTS, **((snapshot or {}).get("config") or {})}
    if not snapshot or not cfg["enabled"]:
        return "\n".join(head) + "\n"
    mgmt = [_net(n) for n in cfg["management_networks"]]
    if not mgmt:
        raise FirewallError("no management network")
    mgmt4 = [str(n) for n in mgmt if n.version == 4]
    mgmt6 = [str(n) for n in mgmt if n.version == 6]
    body = [f"table inet {TABLE} {{"]
    if mgmt4:
        body += ["    set management4 {", "        type ipv4_addr; flags interval;", f"        elements = {{ {', '.join(mgmt4)} }}", "    }"]
    if mgmt6:
        body += ["    set management6 {", "        type ipv6_addr; flags interval;", f"        elements = {{ {', '.join(mgmt6)} }}", "    }"]
    chain = [
        "type filter hook input priority filter; policy drop;",
        "ct state established,related accept",
        "ct state invalid drop",
        'iif "lo" accept',
        "icmp type { destination-unreachable, time-exceeded, parameter-problem } accept",
        "icmp type echo-request limit rate 20/second accept",
        "icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept",
        "icmpv6 type echo-request limit rate 20/second accept",
        "# SSH and the console from the management networks, before every rule: they cannot be locked out.",
    ]
    ports = "{ " + ", ".join(str(p) for p in MANAGEMENT_PORTS) + " }"
    if mgmt4:
        chain.append(f"ip saddr @management4 tcp dport {ports} accept")
    if mgmt6:
        chain.append(f"ip6 saddr @management6 tcp dport {ports} accept")
    chain.append("# Rules (Settings → Firewall), in order.")
    for rule in (snapshot.get("rules") or [])[:MAX_RULES]:
        chain += _rule_lines(rule, now)
    chain.append("# Services.")
    if cfg["dns"]:
        chain += ["udp dport 53 accept", "tcp dport 53 accept"]
    if cfg["dot"]:
        chain.append("tcp dport 853 accept")
    if cfg["doh"]:
        chain.append("tcp dport 443 accept")
    for address in snapshot.get("secondaries") or []:
        ip = ipaddress.ip_address(address)
        chain.append(f"{'ip' if ip.version == 4 else 'ip6'} saddr {ip} tcp dport {SECONDARY_PORT} accept")
    body += ["    chain input {", *(f"        {line}" for line in chain), "    }", "}"]
    return "\n".join(head + body) + "\n"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


# --------------------------------------------------------------------------- the API's side


def status(settings: Settings | None = None) -> dict:
    s = settings or get_settings()
    try:
        return json.loads((s.firewall_status_dir / "status.json").read_text())
    except (OSError, ValueError):
        return {"state": "none"}


def can_apply(settings: Settings | None = None) -> bool:
    d = (settings or get_settings()).firewall_request_dir
    return d.is_dir() and os.access(d, os.W_OK)


def busy(settings: Settings | None = None) -> bool:
    s = settings or get_settings()
    return (s.firewall_request_dir / REQUEST).exists() or status(s).get("state") in ("applying", "confirming")


def _write_request(s: Settings, payload: dict) -> None:
    path = s.firewall_request_dir / REQUEST
    tmp = s.firewall_request_dir / f".{REQUEST}.{secrets.token_hex(4)}"
    tmp.write_text(json.dumps(payload))
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def request_apply(db: Session, actor: str, settings: Settings | None = None) -> dict:
    """Puts the draft live: stores it as the active snapshot (the old one as previous) and asks
    dnsone-firewall to apply it and wait for a confirmation. Returns the snapshot."""
    s = settings or get_settings()
    if not can_apply(s):
        raise FirewallError("The firewall is not set up on this server: run `sudo dnsone-update` (or ops/dnsone-postinstall) once.")
    if busy(s):
        raise FirewallError("A firewall change is being applied; wait for it to finish.")
    snapshot = {**draft(db), "id": secrets.token_hex(8), "by": actor, "at": utcnow().isoformat(timespec="seconds")}
    render(snapshot)  # refuses a snapshot that cannot be rendered before anything is stored
    old = db.get(Setting, ACTIVE_KEY)
    prev = db.get(Setting, PREVIOUS_KEY)
    if old is not None:
        if prev is None:
            db.add(Setting(name=PREVIOUS_KEY, value=dict(old.value)))
        else:
            prev.value = dict(old.value)
        old.value = snapshot
    else:
        db.add(Setting(name=ACTIVE_KEY, value=snapshot))
    db.commit()
    _write_request(s, {"id": snapshot["id"], "confirm": True, "by": actor, "node": s.node_name})
    return snapshot


def confirm(snapshot_id: str, settings: Settings | None = None) -> bool:
    s = settings or get_settings()
    st = status(s)
    if st.get("state") != "confirming" or st.get("id") != snapshot_id:
        return False
    path = s.firewall_request_dir / CONFIRM
    tmp = s.firewall_request_dir / f".{CONFIRM}.{secrets.token_hex(4)}"
    tmp.write_text(snapshot_id)
    os.replace(tmp, path)
    return True


def sync_request(db: Session, settings: Settings | None = None) -> str | None:
    """dnsone-ctl sync: asks for the active snapshot when this node runs other rules (another node's
    Apply, a rule that expired). No confirmation: the operator confirmed on the node they applied on."""
    s = settings or get_settings()
    snap = active(db)
    if snap is None or not can_apply(s) or busy(s):
        return None
    try:
        wanted = digest(render(snap))
    except (FirewallError, ValueError, KeyError) as exc:
        return f"firewall: the active rules cannot be rendered: {exc}"
    st = status(s)
    if st.get("hash") == wanted:
        return None
    _write_request(s, {"id": snap.get("id"), "confirm": False, "by": "sync", "node": s.node_name})
    return "firewall: loading the active rules"


# --------------------------------------------------------------------------- dnsone-firewall (root)


class _Helper:
    def __init__(self, s: Settings):
        self.s = s
        self.status_path = s.firewall_status_dir / "status.json"

    def write_status(self, **values) -> None:
        values["at"] = utcnow().isoformat(timespec="seconds")
        values["ufw_active"] = self.ufw_active()
        tmp = self.status_path.with_suffix(".json.new")
        tmp.write_text(json.dumps(values))
        os.chmod(tmp, 0o640)
        try:
            shutil.chown(tmp, group="dnsone")
        except (LookupError, PermissionError, OSError):
            pass
        os.replace(tmp, self.status_path)

    @staticmethod
    def ufw_active() -> bool:
        try:
            out = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            return False
        return "Status: active" in out

    def nft(self, script: str, check: bool = False) -> tuple[bool, str]:
        cmd = [NFT, *(["-c"] if check else []), "-f", "-"]
        proc = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=30)
        return proc.returncode == 0, (proc.stdout + proc.stderr).strip()

    def current_table(self) -> str:
        """The table as it runs now, as a script that brings it back (or removes it)."""
        proc = subprocess.run([NFT, "list", "table", "inet", TABLE], capture_output=True, text=True, timeout=30)
        head = f"table inet {TABLE}\ndelete table inet {TABLE}\n"
        return head + (proc.stdout if proc.returncode == 0 else "")

    def apply(self) -> int:
        from .db import new_session

        request_path = self.s.firewall_request_dir / REQUEST
        try:
            request = json.loads(request_path.read_text())
        except (OSError, ValueError):
            request = {}
        # Busy before the request disappears, so the console never sees a moment when it may apply again.
        self.write_status(state="applying", id=request.get("id"), message="Applying the rules…")
        request_path.unlink(missing_ok=True)
        (self.s.firewall_request_dir / CONFIRM).unlink(missing_ok=True)
        db = new_session()
        try:
            snap = active(db)
            previous_snap = db.get(Setting, PREVIOUS_KEY)
            previous_value = dict(previous_snap.value) if previous_snap else None
        finally:
            db.close()
        snap_id = (snap or {}).get("id")
        try:
            script = render(snap)
        except (FirewallError, ValueError, KeyError, TypeError) as exc:
            self.write_status(state="failed", id=snap_id, message=f"The rules cannot be rendered: {exc}")
            return 1
        ok, out = self.nft(script, check=True)
        if not ok:
            self.write_status(state="failed", id=snap_id, message=f"nft refused the rules; nothing changed: {out[:2000]}")
            self._restore_snapshot(previous_value, snap_id)
            return 1
        before = self.current_table()
        ok, out = self.nft(script)
        if not ok:
            self.write_status(state="failed", id=snap_id, message=f"nft failed; nothing changed: {out[:2000]}")
            self._restore_snapshot(previous_value, snap_id)
            return 1
        enabled = bool(snap and (snap.get("config") or {}).get("enabled"))
        if request.get("confirm"):
            deadline = time.time() + CONFIRM_SECONDS
            self.write_status(state="confirming", id=snap_id, hash=digest(script), deadline=int(deadline), enabled=enabled,
                              message=f"Applied; waiting for the console to confirm it can still reach the server ({CONFIRM_SECONDS} s).")
            confirm_path = self.s.firewall_request_dir / CONFIRM
            while time.time() < deadline:
                try:
                    if confirm_path.read_text().strip() == snap_id:
                        break
                except OSError:
                    pass
                time.sleep(0.5)
            else:
                self.nft(before)
                self._restore_snapshot(previous_value, snap_id)
                self.write_status(state="rolled_back", id=snap_id, hash=digest(render(previous_value)) if previous_value else None,
                                  message="No confirmation from the console within a minute: the previous rules were put back.")
                return 1
            confirm_path.unlink(missing_ok=True)
        self._save_boot(script)
        self.write_status(state="applied" if enabled else "disabled", id=snap_id, hash=digest(script), enabled=enabled,
                          message="The rules are in force." if enabled else "DNSOne's firewall is off (its table is removed).")
        return 0

    def _restore_snapshot(self, previous: dict | None, failed_id: str | None) -> None:
        """Puts the previous snapshot back as the active one, unless someone applied again meanwhile."""
        from .db import new_session

        db = new_session()
        try:
            row = db.get(Setting, ACTIVE_KEY, with_for_update=True)
            if row is None or row.value.get("id") != failed_id:
                return
            if previous is None:
                db.delete(row)
            else:
                row.value = previous
            db.commit()
        finally:
            db.close()

    def _save_boot(self, script: str) -> None:
        path = self.s.firewall_status_dir / "active.nft"
        tmp = path.with_suffix(".nft.new")
        tmp.write_text(script)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def boot(self) -> int:
        path = self.s.firewall_status_dir / "active.nft"
        if not path.exists():
            return 0
        ok, out = self.nft(path.read_text())
        if not ok:
            print(f"dnsone-firewall: loading {path} failed: {out}", file=sys.stderr)
            return 1
        return 0


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if os.geteuid() != 0:
        print("dnsone-firewall runs as root (dnsone-firewall.service)", file=sys.stderr)
        return 1
    s = get_settings()
    s.firewall_status_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    helper = _Helper(s)
    if args == ["apply"]:
        return helper.apply()
    if args == ["boot"]:
        return helper.boot()
    print("usage: python -m dnsone.firewall apply|boot", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
