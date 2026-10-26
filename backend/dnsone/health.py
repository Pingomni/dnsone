"""Service health: protocol-level probes of every component, not just "is the unit running"."""

from __future__ import annotations

import json
import re
import shutil
import socket
import ssl
import time
from datetime import datetime, timedelta, timezone

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import httpx
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from . import cluster, rpz
from .edition import pro
from .config import Settings, get_settings
from .models import Setting, Zone
from .system import run, utcnow


def _check(name: str, ok: bool, detail: str, level: str | None = None) -> dict:
    return {"name": name, "status": level or ("ok" if ok else "error"), "detail": detail}


def _dns_probe(address: str, port: int, qname: str, rd: bool) -> tuple[bool, str]:
    query = dns.message.make_query(qname, dns.rdatatype.SOA)
    if not rd:
        query.flags &= ~0x0100
    started = time.monotonic()
    try:
        response = dns.query.udp(query, address, port=port, timeout=2)
    except (dns.exception.DNSException, OSError) as exc:
        return False, f"no answer from {address}:{port} ({exc.__class__.__name__})"
    ms = (time.monotonic() - started) * 1000
    return True, f"{dns.rcode.to_text(response.rcode())} in {ms:.0f} ms"


def _recent(stamp: str | None, minutes: int) -> bool:
    """True if an ISO UTC timestamp written by dnsone-querylog is within the last `minutes`."""
    if not stamp:
        return False
    return stamp[:19] >= (utcnow() - timedelta(minutes=minutes)).isoformat(timespec="seconds")


def _api(url: str, key: str) -> tuple[bool, str]:
    if not key:
        return False, "API key not configured"
    try:
        response = httpx.get(f"{url}/api/v1/servers/localhost", headers={"X-API-Key": key}, timeout=2)
        response.raise_for_status()
        info = response.json()
        return True, f"{info.get('daemon_type', 'up')} {info.get('version', '')}".strip()
    except (httpx.HTTPError, ValueError) as exc:
        return False, f"API unreachable ({exc.__class__.__name__})"


CERT_WARN_DAYS = 14


def encrypted_frontends(s: Settings) -> list[dict] | None:
    """dnsdist's DoT and DoH listeners ({"address", "type"}); None if its API is unreachable."""
    if not s.dnsdist_api_key:
        return None
    try:
        response = httpx.get(f"{s.dnsdist_api_url}/api/v1/servers/localhost", headers={"X-API-Key": s.dnsdist_api_key}, timeout=2)
        response.raise_for_status()
        frontends = response.json().get("frontends", [])
    except (httpx.HTTPError, ValueError):
        return None
    out = []
    for f in frontends:
        kind = "DoT" if "DNS over TLS" in f.get("type", "") else "DoH" if "DNS over HTTPS" in f.get("type", "") else None
        if kind and not any(o["address"] == f.get("address") for o in out):
            out.append({"address": f.get("address", ""), "type": kind})
    return out


def certificate_days(address: str) -> tuple[int, str]:
    """Days until the certificate a TLS listener presents expires, and its subject. Raises OSError."""
    from cryptography import x509
    host, _, port = address.rpartition(":")
    host = host.strip("[]")
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1" if host == "0.0.0.0" else "::1"
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # only reading the certificate's dates, not trusting the peer
    with socket.create_connection((host, int(port)), timeout=3) as sock, context.wrap_socket(sock) as tls:
        der = tls.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    left = cert.not_valid_after_utc - datetime.now(timezone.utc)
    return left.days, names[0].value if names else "(no CN)"


def _encrypted_check(s: Settings) -> dict:
    frontends = encrypted_frontends(s)
    if frontends is None:
        return _check("Encrypted DNS", False, "dnsdist API unreachable", "warning")
    if not frontends:
        return _check("Encrypted DNS", True, "off (ENCRYPTED_DNS in dnsdist.conf)")
    listening = ", ".join(f"{f['type']} {f['address']}" for f in frontends)
    try:
        days, subject = certificate_days(frontends[0]["address"])
    except (OSError, ValueError) as exc:
        return _check("Encrypted DNS", False, f"{listening}; TLS handshake failed ({exc.__class__.__name__})")
    if days < 0:
        return _check("Encrypted DNS", False, f"{listening}; the certificate for {subject} has EXPIRED: phones and browsers stop using this resolver")
    detail = f"{listening}; certificate {subject} valid for {days} more days"
    return _check("Encrypted DNS", days >= CERT_WARN_DAYS, detail, None if days >= CERT_WARN_DAYS else "warning")


def checks(db: Session, settings: Settings | None = None, cheap: bool = False) -> list[dict]:
    """All probes. cheap=True skips the ones that start processes (for the unauthenticated endpoint)."""
    s = settings or get_settings()
    out = []

    try:
        db.execute(text("SELECT 1"))
        out.append(_check("MySQL", True, "connected"))
    except Exception as exc:  # noqa: BLE001
        out.append(_check("MySQL", False, str(exc)[:200]))
        return out

    if not cheap:
        code, msg = run([s.rndc, "-k", str(s.rndc_key), "-s", s.rndc_server, "-p", str(s.rndc_port), "status"], timeout=5)
        line = next((ln for ln in msg.splitlines() if ln.startswith("number of zones")), msg.splitlines()[0] if msg else "")
        out.append(_check("BIND (rndc)", code == 0, line if code == 0 else msg[:200]))
    sample = db.scalar(select(Zone.name).where(Zone.status == "active", Zone.published_serial.is_not(None)).limit(1))
    ok, detail = _dns_probe(s.bind_address, s.bind_port, f"{sample or 'localhost'}.", rd=False)
    out.append(_check("BIND (DNS)", ok, detail))

    ok, detail = _api(s.recursor_api_url, s.recursor_api_key)
    out.append(_check("PowerDNS Recursor", ok, detail))
    ok, detail = _api(s.dnsdist_api_url, s.dnsdist_api_key)
    out.append(_check("dnsdist", ok, detail))
    if ok and not cheap:
        out.append(_encrypted_check(s))

    errors = db.scalar(select(func.count()).select_from(Zone).where(Zone.publish_state == "error")) or 0
    stale = db.scalar(select(func.count()).select_from(Zone).where(Zone.publish_state == "pending", Zone.updated_at < utcnow() - timedelta(minutes=10))) or 0
    if errors:
        out.append(_check("Zone publishing", False, f"{errors} zone(s) failed to publish"))
    elif stale:
        out.append(_check("Zone publishing", False, f"{stale} zone(s) pending for over 10 minutes", "warning"))
    else:
        out.append(_check("Zone publishing", True, "all zones published"))

    state = rpz.get_state(db)
    if state.get("state") == "error":
        out.append(_check("RPZ", False, "last build failed"))
    elif state.get("state") == "never":
        out.append(_check("RPZ", False, "not built yet: run dnsone-ctl rpz build", "warning"))
    else:
        out.append(_check("RPZ", True, f"serial {state.get('serial')}, {state.get('entries', 0)} triggers"))

    if s.querylog_mode == "off":
        out.append(_check("Query log", True, "off (DNSONE_QUERYLOG_MODE)"))
    else:
        row = db.get(Setting, f"querylog.state.{s.node_name}"[:64])
        state = row.value if row else {}
        if not _recent(state.get("updated_at"), minutes=3):
            out.append(_check("Query log", False, "dnsone-querylog is not running", "warning"))
        elif not _recent(state.get("last_message_at"), minutes=5):
            out.append(_check("Query log", False, "no data from the Recursor (check protobufServer in recursor.lua)", "warning"))
        else:
            out.append(_check("Query log", True, f"{state.get('mode')}: {state.get('received', 0):,} answers since start, {state.get('dropped', 0):,} dropped"))
        export = state.get("export") or {}
        if export.get("enabled"):
            failing = export.get("error")
            out.append(_check("Query log export", not failing, f"syslog: {export.get('sent', 0):,} sent, {export.get('dropped', 0):,} dropped"
                              + (f"; {failing}" if failing else ""), "warning" if failing else None))

    from . import runtime
    if runtime.server_settings(db, s).get("ddns", "off") != "off":
        host, _, port = s.ddns_listen.rpartition(":")
        ok, detail = _dns_probe(host.strip("[]"), int(port), "health.ddns.dnsone.", rd=False)
        out.append(_check("Dynamic DNS", ok, detail if ok else f"{detail}: is dnsone-ddns running?"))

    out += _runtime_checks(db, s)

    firewall = pro("firewall")
    if firewall is not None and firewall.active(db) is not None:
        st = firewall.status(s)
        state = st.get("state", "none")
        if state in ("applied", "disabled", "applying", "confirming"):
            out.append(_check("Firewall", True, "on: the rules are in force" if state == "applied" else "off" if state == "disabled" else state))
        else:
            out.append(_check("Firewall", False, st.get("message") or "the rules applied in the console are not in force on this node", "warning"))

    for label, path in (("Disk (zones)", s.zones_dir), ("Disk (data)", s.rpz_file.parent)):
        try:
            usage = shutil.disk_usage(path)
            free = usage.free / usage.total * 100
            out.append(_check(label, free > 10, f"{free:.0f}% free", None if free > 10 else ("error" if free < 5 else "warning")))
        except OSError as exc:
            out.append(_check(label, False, str(exc)))
    return out


def _file_serial(path, pattern: str) -> int | None:
    try:
        match = re.search(pattern, path.read_text(encoding="utf-8"))
    except OSError:
        return None
    return int(match.group(1)) if match else None


def _runtime_checks(db: Session, s: Settings) -> list[dict]:
    """The daemons run with the data DNSOne last wrote (runtime.py): groups, pauses, regex, server settings."""
    out = []
    running = cluster.daemon_serials(s)
    try:
        written = json.loads(s.recursor_policy_file.with_suffix(".json").read_text()).get("serial")
    except (OSError, ValueError):
        written = None
    if written is None:
        out.append(_check("Client policies", False, "policy data not written yet: run dnsone-ctl sync", "warning"))
    elif running["recursor_policy"] is None:
        out.append(_check("Client policies", False, "the Recursor does not run the DNSOne policy script (lua-dns-script=/etc/powerdns/dnsone.lua)", "warning"))
    elif running["recursor_policy"] != written:
        out.append(_check("Client policies", False, "the Recursor runs older policy data: run dnsone-ctl sync", "warning"))
    else:
        out.append(_check("Client policies", True, "the Recursor runs the current groups, pauses and regex rules"))

    written = _file_serial(s.dnsdist_settings_file, r'\["serial"\] = (\d+)')
    if written is None:
        out.append(_check("DNS server settings", False, "not written yet: run dnsone-ctl sync", "warning"))
    elif running["dnsdist_settings"] is None:
        out.append(_check("DNS server settings", False, "dnsdist does not report DNSOne's settings (update /etc/dnsdist/dnsdist.conf)", "warning"))
    elif running["dnsdist_settings"] != written:
        out.append(_check("DNS server settings", False, "dnsdist runs older settings; it re-reads them every 2 s: check its log", "warning"))
    else:
        out.append(_check("DNS server settings", True, "dnsdist runs the current networks, rate limits and regex rules"))

    nodes = cluster.nodes(db)
    if len(nodes) > 1:
        stale = [n["node"] for n in nodes if n["stale"]]
        out.append(_check("Cluster", not stale, f"{len(nodes)} nodes" + (f"; not syncing: {', '.join(stale)}" if stale else ", all syncing"),
                          None if not stale else "warning"))
    return out


def overall(results: list[dict]) -> str:
    if any(r["status"] == "error" for r in results):
        return "error"
    if any(r["status"] == "warning" for r in results):
        return "warning"
    return "ok"
