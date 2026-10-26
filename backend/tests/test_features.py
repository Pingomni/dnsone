"""End-to-end tests of the features after Phase 1: client groups, regex rules, allowlists, pausing,
the null-IP answer, DNS server settings, query log classification and privacy, two-factor sign-in,
app passwords, backup and restore, and clustering (catalog zone, secondaries, the replica role).

Same test stack as test_integration.py. Customers are told apart by source address: dnsdist sees
127.0.0.1-3 (any loopback address works) and hands it to the Recursor with the PROXY protocol.
DNSONE_TEST_SECONDARY (host:port) is a BIND secondary that follows the catalog zone (see
docs/RUNBOOK.md, Phase 2); the clustering test is skipped without it.
"""

from __future__ import annotations

import dataclasses
import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from helpers import ENV, PASSWORD, bind_serial, eventually, has, local_address, needs

pytestmark = pytest.mark.skipif(not ENV or not os.environ.get("DNSONE_TEST_DNSDIST"), reason="DNSONE_TEST_ENV / DNSONE_TEST_DNSDIST not set")

DEFAULT_IP, FAMILY_IP, OPEN_IP, OTHER_IP = "127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"
D = "dnsone-test.example"

LISTS = {
    "/ads.txt": f"0.0.0.0 ads.{D}\n0.0.0.0 both.{D}\n0.0.0.0 allowlisted.{D}\n0.0.0.0 rx2.{D}\n",
    "/family.txt": f"adult.{D}\n",
    "/allow.txt": f"allowlisted.{D}\n",
}


def ask(name: str, source: str = DEFAULT_IP, rtype: str = "A"):
    import dns.message
    import dns.query
    import dns.rdatatype
    host, _, port = os.environ["DNSONE_TEST_DNSDIST"].rpartition(":")
    query = dns.message.make_query(name, getattr(dns.rdatatype, rtype), use_edns=0)
    return dns.query.udp(query, host, port=int(port), timeout=5, source=source)


def try_ask(name: str, source: str):
    """The response, or None when dnsdist drops the query (its ACL)."""
    import dns.exception
    try:
        return ask(name, source)
    except dns.exception.Timeout:
        return None


def rcode_or_silence(name: str, source: str) -> int | None:
    response = try_ask(name, source)
    return None if response is None else response.rcode()


def blocked(name: str, source: str = DEFAULT_IP) -> bool:
    """Blocked answers carry Extended DNS Error 15 ("Blocked"), whatever the block action."""
    import dns.edns
    return any(isinstance(o, dns.edns.EDEOption) and o.code == 15 for o in ask(name, source).options)


@pytest.fixture(scope="module")
def lists_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = LISTS.get(self.path)
            self.send_response(200 if body else 404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write((body or "").encode())

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(scope="module")
def setup(client, lists_server):
    """Default: ads list + allowlist. Family (127.0.0.2/31): ads + family lists. Open (127.0.0.3): no blocking."""
    ads = client.post("/api/rpz/blocklists", json={"name": "Ads", "url": f"{lists_server}/ads.txt"}).json()
    allow = client.post("/api/rpz/blocklists", json={"name": "Allow", "url": f"{lists_server}/allow.txt", "kind": "allow"}).json()
    family_list = client.post("/api/rpz/blocklists", json={"name": "Family", "url": f"{lists_server}/family.txt", "group_ids": []}).json()
    assert ads["kind"] == "block" and allow["kind"] == "allow" and family_list["groups"] == []
    family = client.post("/api/groups", json={"name": "Family", "blocklist_ids": [ads["id"], family_list["id"]]})
    assert family.status_code == 201, family.text
    family = family.json()
    open_ = client.post("/api/groups", json={"name": "Open", "blocking": False}).json()
    assert client.post(f"/api/groups/{family['id']}/networks", json={"network": "127.0.0.2/31"}).status_code == 201
    assert client.post(f"/api/groups/{open_['id']}/networks", json={"network": OPEN_IP}).json()["network"] == "127.0.0.3/32"
    # The build ran in the background of the last request.
    state = client.get("/api/rpz/status").json()["state"]
    assert state["state"] == "ok" and state["policies"] == ["dnsone-legal"] * has("legal") + ["dnsone-allow", "dnsone", f"dnsone-g{family['id']}-allow", f"dnsone-g{family['id']}"], state
    return {"ads": ads, "allow": allow, "family_list": family_list, "family": family, "open": open_}


def test_groups_and_lists(client, setup):
    assert blocked(f"ads.{D}", DEFAULT_IP) and blocked(f"ads.{D}", FAMILY_IP) and not blocked(f"ads.{D}", OPEN_IP)
    assert not blocked(f"adult.{D}", DEFAULT_IP) and blocked(f"adult.{D}", FAMILY_IP)
    assert blocked(f"sub.adult.{D}", FAMILY_IP)  # block_subdomains
    # The allowlist subscription is the Default group's only.
    assert not blocked(f"allowlisted.{D}", DEFAULT_IP) and blocked(f"allowlisted.{D}", FAMILY_IP)
    assert ask("www.example.com.", OPEN_IP).rcode() == 0

    family, open_ = setup["family"], setup["open"]
    found = client.get("/api/groups/lookup", params={"client": OPEN_IP}).json()
    assert found["group"]["name"] == "Open" and found["network"] == "127.0.0.3/32"  # the most specific network wins
    assert client.get("/api/groups/lookup", params={"client": FAMILY_IP}).json()["network"] == "127.0.0.2/31"
    assert client.get("/api/groups/lookup", params={"client": "192.0.2.1"}).json()["group"]["name"] == "Default"

    groups = {g["name"]: g for g in client.get("/api/groups").json()["rows"]}
    assert groups["Default"]["built_in"] and groups["Family"]["networks"] == 1 and groups["Family"]["entries"] == 10
    assert not groups["Open"]["blocking"] and groups["Open"]["entries"] is None

    rpz_file = Path(os.environ["DNSONE_RPZ_FILE"])
    assert rpz_file.with_name(f"{rpz_file.stem}-g{family['id']}{rpz_file.suffix}").exists()
    assert not rpz_file.with_name(f"{rpz_file.stem}-g{open_['id']}{rpz_file.suffix}").exists()
    look = client.get("/api/rpz/lookup", params={"domain": f"adult.{D}", "group_id": family["id"]}).json()
    assert look["blocked"] and look["blocklists"][0]["blocklist"] == "Family"
    look = client.get("/api/rpz/lookup", params={"domain": f"allowlisted.{D}"}).json()
    assert look["allowed"] and look["allowlists"][0]["blocklist"] == "Allow"

    # Validation and protection of the Default group.
    default = groups["Default"]
    assert client.delete(f"/api/groups/{default['id']}").status_code == 422
    assert client.post(f"/api/groups/{default['id']}/networks", json={"network": "10.0.0.0/8"}).status_code == 422
    dup = client.post(f"/api/groups/{open_['id']}/networks", json={"network": "127.0.0.2/31"})
    assert dup.status_code == 422 and "group Family" in dup.json()["message"]
    assert client.post(f"/api/groups/{open_['id']}/networks", json={"network": "not-a-net"}).status_code == 422
    assert client.post("/api/groups", json={"name": "Family"}).status_code == 409
    imported = client.post(f"/api/groups/{open_['id']}/networks/import", json={"text": "198.51.100.0/24 # shop\n2001:db8::/48\nbad\n127.0.0.3\n"}).json()
    assert imported["added"] == 2 and imported["skipped_count"] == 2


def test_group_rules_override_global(client, setup):
    family = setup["family"]
    glob = client.post("/api/rpz/rules", json={"pattern": f"rule.{D}", "action": "block"})
    assert glob.status_code == 201
    assert client.post("/api/rpz/rules", json={"pattern": f"rule.{D}", "action": "block"}).status_code == 409
    mine = client.post("/api/rpz/rules", json={"pattern": f"rule.{D}", "action": "allow", "group_id": family["id"]})
    assert mine.status_code == 201 and mine.json()["group"] == "Family"
    assert blocked(f"rule.{D}", DEFAULT_IP) and not blocked(f"rule.{D}", FAMILY_IP)
    listed = client.get("/api/rpz/rules", params={"group": str(family["id"])}).json()
    assert listed["total"] == 1 and listed["rows"][0]["action"] == "allow"
    assert client.get("/api/rpz/rules", params={"group": "all"}).json()["total"] == 1


def test_regex_rules(client, setup):
    bad = client.post("/api/rpz/rules", json={"pattern": r"^ads\d+\.", "match_type": "regex", "action": "block"})
    assert bad.status_code == 422 and "POSIX" in bad.json()["message"]
    assert client.post("/api/rpz/rules", json={"pattern": ".*", "match_type": "regex", "action": "block"}).status_code == 422
    assert client.post("/api/rpz/rules", json={"pattern": "x", "match_type": "regex", "action": "nxdomain"}).status_code == 422

    rx = client.post("/api/rpz/rules", json={"pattern": rf"^rx[0-9]+\.{D.replace('.', chr(92) + '.')}$", "match_type": "regex", "action": "block"})
    assert rx.status_code == 201, rx.text
    # dnsdist picks the rule up within 2 s.
    assert eventually(lambda: blocked(f"rx1.{D}", DEFAULT_IP))
    assert blocked(f"rx7.{D}", FAMILY_IP) and not blocked(f"rx1.{D}", OPEN_IP) and not blocked(f"xrx1.{D}", DEFAULT_IP)
    # An exact allow rule (RPZ passthru) wins over a regex block.
    client.post("/api/rpz/rules", json={"pattern": f"rx3.{D}", "action": "allow"})
    assert not blocked(f"rx3.{D}", DEFAULT_IP)

    # A regex allow rule for one group lifts every block for it, lists included.
    allow = client.post("/api/rpz/rules", json={"pattern": r"^ads\.", "match_type": "regex", "action": "allow", "group_id": setup["family"]["id"]})
    assert allow.status_code == 201
    assert eventually(lambda: not blocked(f"ads.{D}", FAMILY_IP))
    assert blocked(f"ads.{D}", DEFAULT_IP)
    look = client.get("/api/rpz/lookup", params={"domain": f"ads.{D}", "group_id": setup["family"]["id"]}).json()
    assert look["allowed"] and any(r["pattern"] == r"^ads\." for r in look["rules"])

    # Disabling takes effect at once: regex-blocked answers are not cached.
    client.patch(f"/api/rpz/rules/{rx.json()['id']}", json={"enabled": False})
    assert eventually(lambda: not blocked(f"rx1.{D}", DEFAULT_IP))
    client.patch(f"/api/rpz/rules/{rx.json()['id']}", json={"enabled": True})
    assert eventually(lambda: blocked(f"rx1.{D}", DEFAULT_IP))
    assert client.get("/api/rpz/rules", params={"match_type": "regex"}).json()["total"] == 2


def test_pause(client, setup):
    default = next(g for g in client.get("/api/groups").json()["rows"] if g["built_in"])
    paused = client.post("/api/rpz/pause", json={"minutes": 5, "group_id": default["id"]})
    assert paused.status_code == 200
    assert paused.json()["groups"][0]["name"] == "Default" and paused.json()["groups"][0]["until"]
    assert not blocked(f"ads.{D}", DEFAULT_IP) and not blocked(f"rx1.{D}", DEFAULT_IP)
    assert blocked(f"adult.{D}", FAMILY_IP)
    assert client.delete("/api/rpz/pause", params={"group_id": paused.json()["groups"][0]["id"]}).status_code == 200
    assert blocked(f"ads.{D}", DEFAULT_IP)

    everyone = client.post("/api/rpz/pause", json={"minutes": 0}).json()
    assert everyone["all"] == "forever"
    assert not blocked(f"adult.{D}", FAMILY_IP) and not blocked(f"ads.{D}", DEFAULT_IP)
    assert client.get("/api/rpz/status").json()["pause"]["all"] == "forever"
    client.delete("/api/rpz/pause")
    assert blocked(f"adult.{D}", FAMILY_IP) and blocked(f"ads.{D}", DEFAULT_IP)
    assert client.post("/api/rpz/pause", json={"minutes": 5, "group_id": 999999}).status_code == 422
    assert client.get("/api/audit", params={"action": "rpz.paused"}).json()["total"] == 2


def test_null_ip_answer(client, setup):
    assert client.put("/api/rpz/policy", json={"action": "null_ip", "block_subdomains": True}).status_code == 200
    import dns.rdatatype

    def values(name, rtype):
        return [rr.to_text() for rrset in ask(name, DEFAULT_IP, rtype).answer for rr in rrset if rrset.rdtype == getattr(dns.rdatatype, rtype)]

    assert eventually(lambda: values(f"ads.{D}", "A") == ["0.0.0.0"])
    assert values(f"ads.{D}", "AAAA") == ["::"]
    # Regex blocks answer the same way (the policy script).
    assert eventually(lambda: values(f"rx5.{D}", "A") == ["0.0.0.0"])
    assert "A\t0.0.0.0" in Path(os.environ["DNSONE_RPZ_FILE"]).read_text()
    client.put("/api/rpz/policy", json={"action": "nxdomain", "block_subdomains": True})
    assert eventually(lambda: ask(f"ads.{D}", DEFAULT_IP).rcode() == 3)


def test_dns_server_settings(client, setup):
    me = local_address()
    current = client.get("/api/settings/dns-server").json()
    assert current["stored"] is False and current["client_qps"] == 200
    body = {"client_networks": ["10.0.0.0/8"], "nat_addresses": [], "client_qps": 200, "client_burst": 400,
            "nat_qps": 5000, "nat_burst": 10000, "public_authoritative": False}
    assert client.put("/api/settings/dns-server", json={**body, "client_networks": []}).status_code == 422
    assert client.put("/api/settings/dns-server", json={**body, "client_burst": 10}).json()["errors"] == {"client_burst": "The burst must be at least the rate."}
    assert client.put("/api/settings/dns-server", json={**body, "client_networks": ["nope"]}).json()["errors"].get("client_networks.0")

    saved = client.put("/api/settings/dns-server", json=body).json()
    assert saved["stored"] and saved["client_networks"] == ["10.0.0.0/8"]
    assert "10.0.0.0/8" in Path(os.environ["DNSONE_RECURSOR_ALLOW_FROM_FILE"]).read_text()

    def health(name):
        return next(c for c in client.get("/api/system/health").json()["checks"] if c["name"] == name)["status"]

    assert eventually(lambda: health("DNS server settings") == "ok")
    assert rcode_or_silence("www.example.com.", me) is None  # not a customer, no public DNS: the ACL drops it
    client.put("/api/settings/dns-server", json={**body, "client_networks": ["10.0.0.0/8", f"{me}/32"], "nat_addresses": ["198.51.100.0/28"]})
    assert eventually(lambda: rcode_or_silence("www.example.com.", me) == 0)
    assert health("Client policies") == "ok"

    # Public authoritative: everyone may ask for hosted zones, nothing else.
    zone = client.post("/api/zones", json={"name": "pub-it.test", "soa_rname": "hostmaster@pub-it.test",
                                            "nameservers": [{"host": "ns1", "address": "192.0.2.53"}]}).json()
    client.post(f"/api/zones/{zone['id']}/records", json={"name": "www", "type": "A", "value": "192.0.2.7"})
    client.put("/api/settings/dns-server", json={**body, "public_authoritative": True})
    # dnsdist re-reads the hosted zones every 30 s.
    answer = eventually(lambda: (lambda r: r if r is not None and r.rcode() == 0 else None)(try_ask("www.pub-it.test.", me)), timeout=40, interval=1)
    assert answer and answer.answer[0][0].to_text() == "192.0.2.7"
    assert ask("www.example.com.", me).rcode() == 5
    client.delete(f"/api/zones/{zone['id']}")
    client.put("/api/settings/dns-server", json={**body, "client_networks": ["10.0.0.0/8"], "public_authoritative": True})


@pytest.fixture(scope="module")
def collector():
    """dnsone-querylog, listening where the test Recursor sends its protobuf stream."""
    env = {**os.environ, "DNSONE_ENV_FILE": "/nonexistent"}
    proc = subprocess.Popen([str(Path(sys.executable).with_name("dnsone-querylog"))], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    host, _, port = os.environ["DNSONE_QUERYLOG_LISTEN"].rpartition(":")

    def listening():
        with socket.socket() as s:
            return s.connect_ex((host, int(port))) == 0

    assert eventually(listening, timeout=10)
    time.sleep(3)  # the Recursor reconnects every 2 s
    yield proc

    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)


def _rows(api, **params):
    return api.get("/api/queries", params={"limit": 500, **params}).json()["rows"]


def test_query_log_classification(client, setup, collector):
    # 127.0.0.1 is in DNSONE_QUERYLOG_IGNORE_CLIENTS (dnsdist's health checks): another Default client.
    for name, source in ((f"ads.{D}", OTHER_IP), (f"ads.{D}", OPEN_IP), (f"adult.{D}", FAMILY_IP), (f"allowlisted.{D}", OTHER_IP),
                         (f"rx1.{D}", OTHER_IP), (f"rule.{D}", FAMILY_IP), (f"ads.{D}", FAMILY_IP)):
        ask(name, source)
    time.sleep(3)

    def status(client_ip, qname):
        rows = [r for r in _rows(client, client=client_ip, qname=qname)]
        return rows[0]["status"] if rows else None

    assert eventually(lambda: status(OTHER_IP, f"ads.{D}") == "blocked", timeout=6)
    assert status(OPEN_IP, f"ads.{D}") == "ok"            # blocking off for Open
    assert status(FAMILY_IP, f"adult.{D}") == "blocked"   # Family's own list
    assert status(OTHER_IP, f"allowlisted.{D}") == "allowed"
    assert status(OTHER_IP, f"rx1.{D}") == "blocked"    # regex
    assert status(FAMILY_IP, f"rule.{D}") == "allowed"    # Family's allow rule
    assert status(FAMILY_IP, f"ads.{D}") == "allowed"     # Family's regex allow rule
    assert any(r["latency_ms"] is not None for r in _rows(client, client=OTHER_IP))


def test_privacy_levels(client, setup, collector):
    assert client.put("/api/settings/privacy", json={"level": 1, "retention_hours": 10_000}).status_code == 422
    assert client.put("/api/settings/privacy", json={"level": 1, "retention_hours": 12}).json()["level"] == 1
    time.sleep(16)  # dnsone-querylog re-reads the privacy settings every 15 s
    ask(f"private.{D}", OTHER_IP)
    assert eventually(lambda: any(r["qname"] == "hidden" for r in _rows(client, client=OTHER_IP)), timeout=6)
    assert not _rows(client, qname=f"private.{D}")

    client.put("/api/settings/privacy", json={"level": 3, "retention_hours": 12})
    time.sleep(16)
    before = len(_rows(client))
    ask(f"anonymous.{D}", FAMILY_IP)
    time.sleep(3)
    assert len(_rows(client)) == before
    client.put("/api/settings/privacy", json={"level": 0, "retention_hours": 24})
    assert client.get("/api/queries/summary").json()["privacy_level"] == 0

    # Stopping the collector writes the minute's counters: history and top lists.
    collector.send_signal(signal.SIGTERM)
    collector.wait(timeout=20)
    history = client.get("/api/queries/history", params={"days": 2}).json()["series"]
    assert history and history[-1]["blocked"] >= 3 and history[-1]["total"] >= 9
    top = client.get("/api/queries/top", params={"dimension": "blocked", "hours": 1}).json()["rows"]
    assert {f"ads.{D}", f"rx1.{D}"} <= {r["item"] for r in top}
    clients = {r["item"] for r in client.get("/api/queries/top", params={"dimension": "client", "hours": 1}).json()["rows"]}
    assert {OTHER_IP, FAMILY_IP, OPEN_IP} <= clients

    erased = client.delete("/api/queries").json()
    assert erased["rows"] >= 9 and not _rows(client)


def test_two_factor_and_app_passwords(client, setup):
    from fastapi.testclient import TestClient

    from dnsone import security
    operator = next(r for r in client.get("/api/roles").json()["roles"] if r["name"] == "operator")
    user = client.post("/api/users", json={"username": "op2fa", "role_id": operator["id"], "password": PASSWORD}).json()
    op = TestClient(client.app)
    me = op.post("/api/auth/login", json={"username": "op2fa", "password": PASSWORD}).json()
    op.headers["X-CSRF-Token"] = me["csrf"]
    assert me["user"]["two_factor_enabled"] is False

    assert op.post("/api/auth/2fa/setup", json={"password": "wrong"}).status_code == 422
    setup_2fa = op.post("/api/auth/2fa/setup", json={"password": PASSWORD}).json()
    assert setup_2fa["uri"].startswith("otpauth://totp/DNSOne%3Aop2fa?secret=") and setup_2fa["qr"].startswith("data:image/svg+xml")
    secret = setup_2fa["secret"]
    step = int(time.time() // 30)
    assert op.post("/api/auth/2fa/enable", json={"code": "000000" if security.totp_code(secret, step) != "000000" else "111111"}).status_code == 422
    enabled = op.post("/api/auth/2fa/enable", json={"code": security.totp_code(secret, step)}).json()
    assert enabled["enabled"] and len(enabled["recovery_codes"]) == 10
    assert op.get("/api/auth/2fa").json() == {"enabled": True, "recovery_codes_left": 10}

    # Sign-in now takes two steps; a code works once, a recovery code once.
    fresh = TestClient(client.app)
    first = fresh.post("/api/auth/login", json={"username": "op2fa", "password": PASSWORD}).json()
    assert first["two_factor_required"] and "csrf" not in first
    assert fresh.get("/api/auth/me").status_code == 401
    reused = fresh.post("/api/auth/login/verify", json={"ticket": first["ticket"], "code": security.totp_code(secret, step)})
    assert reused.status_code == 401  # the enrolment code was already used
    ok = fresh.post("/api/auth/login/verify", json={"ticket": first["ticket"], "code": security.totp_code(secret, step + 1)})
    assert ok.status_code == 200 and ok.json()["user"]["two_factor_enabled"] is True
    assert fresh.post("/api/auth/login/verify", json={"ticket": first["ticket"], "code": security.totp_code(secret, step + 1)}).status_code == 401

    other = TestClient(client.app)
    ticket = other.post("/api/auth/login", json={"username": "op2fa", "password": PASSWORD}).json()["ticket"]
    code = enabled["recovery_codes"][0]
    assert other.post("/api/auth/login/verify", json={"ticket": ticket, "code": code.upper()}).status_code == 200
    ticket = TestClient(client.app).post("/api/auth/login", json={"username": "op2fa", "password": PASSWORD}).json()["ticket"]
    assert TestClient(client.app).post("/api/auth/login/verify", json={"ticket": ticket, "code": code}).status_code == 401
    assert client.get("/api/users", params={"q": "op2fa"}).json()["rows"][0]["two_factor_enabled"] is True

    # App passwords: read-only and full; no CSRF; no account-security changes; revocable.
    fresh.headers["X-CSRF-Token"] = ok.json()["csrf"]
    ro = fresh.post("/api/auth/tokens", json={"name": "monitoring", "read_only": True}).json()
    rw = fresh.post("/api/auth/tokens", json={"name": "automation", "read_only": False, "expires_days": 30}).json()
    assert ro["token"].startswith("dno_") and ro["prefix"] == ro["token"][:12] and rw["expires_at"]
    script = TestClient(client.app)
    assert script.get("/api/zones", headers={"Authorization": f"Bearer {ro['token']}"}).status_code == 200
    assert script.post("/api/rpz/rules", json={"pattern": f"t.{D}", "action": "block"}, headers={"Authorization": f"Bearer {ro['token']}"}).status_code == 403
    made = script.post("/api/rpz/rules", json={"pattern": f"t.{D}", "action": "block"}, headers={"Authorization": f"Bearer {rw['token']}"})
    assert made.status_code == 201 and made.json()["created_by"] == "op2fa"
    assert script.get("/api/auth/tokens", headers={"Authorization": f"Bearer {rw['token']}"}).status_code == 403
    assert script.get("/api/users", headers={"Authorization": f"Bearer {rw['token']}"}).status_code == 403  # the operator role
    assert script.get("/api/zones", headers={"Authorization": "Bearer dno_nope"}).status_code == 401
    listed = fresh.get("/api/auth/tokens").json()["rows"]
    assert {t["name"] for t in listed} == {"monitoring", "automation"} and all("token" not in t for t in listed)
    assert next(t for t in listed if t["name"] == "monitoring")["last_used_at"]
    assert fresh.delete(f"/api/auth/tokens/{ro['id']}").status_code == 200
    assert script.get("/api/zones", headers={"Authorization": f"Bearer {ro['token']}"}).status_code == 401
    assert client.get(f"/api/users/{user['id']}/tokens").json()["rows"][0]["name"] == "automation"
    assert client.delete(f"/api/users/{user['id']}/tokens/{rw['id']}").status_code == 200

    # Turning it off needs the password and a code; an administrator can reset it.
    assert fresh.post("/api/auth/2fa/disable", json={"password": PASSWORD, "code": "123"}).status_code == 422
    assert fresh.post("/api/auth/2fa/recovery-codes", json={"password": PASSWORD}).json()["recovery_codes"]
    assert client.patch(f"/api/users/{user['id']}", json={"reset_two_factor": True}).status_code == 200
    assert TestClient(client.app).post("/api/auth/login", json={"username": "op2fa", "password": PASSWORD}).json()["user"]["two_factor_enabled"] is False
    client.delete(f"/api/users/{user['id']}")


def test_backup_and_restore(client, setup):
    zone = client.post("/api/zones", json={"name": "backup-it.test", "soa_rname": "hostmaster@backup-it.test",
                                            "nameservers": [{"host": "ns1", "address": "192.0.2.53"}]}).json()
    client.post(f"/api/zones/{zone['id']}/records", json={"name": "@", "type": "TXT", "value": 'say "hi"'})
    client.put("/api/settings/privacy", json={"level": 1, "retention_hours": 6})
    response = client.get("/api/settings/backup")
    assert response.status_code == 200 and "attachment" in response.headers["content-disposition"]
    data = response.json()
    assert data["dnsone_backup"] == 1 and data["sections"] == ["zones", "ad_blocking", "settings"] + ["legal"] * has("legal")
    assert {g["name"] for g in data["groups"]} == {"Default", "Family", "Open"} and data["privacy"]["level"] == 1
    assert any(r["match_type"] == "regex" and r["group"] == "Family" for r in data["rules"])
    assert "users" not in data and "password" not in json.dumps(data)

    # Lose things, then restore.
    family = setup["family"]
    assert client.delete(f"/api/groups/{family['id']}").status_code == 200
    assert eventually(lambda: not blocked(f"adult.{D}", FAMILY_IP))
    client.delete(f"/api/zones/{zone['id']}")
    client.put("/api/settings/privacy", json={"level": 0, "retention_hours": 24})
    assert bind_serial("backup-it.test") is None

    assert client.post("/api/settings/restore", json={"backup": {"x": 1}, "sections": ["zones"]}).status_code == 422
    partial = {k: v for k, v in data.items() if k != "zones"} | {"sections": ["ad_blocking", "settings"]}
    assert client.post("/api/settings/restore", json={"backup": partial, "sections": ["zones"]}).status_code == 422

    report = client.post("/api/settings/restore", json={"backup": data, "sections": ["zones", "ad_blocking", "settings"]})
    assert report.status_code == 200, report.text
    report = report.json()
    assert report["zones"] == 1 and report["groups"] == 2 and report["blocklists"] == 3 and report["skipped_count"] == 0, report
    assert bind_serial("backup-it.test") is not None
    assert eventually(lambda: blocked(f"adult.{D}", FAMILY_IP))  # Family, its list and network are back
    assert eventually(lambda: not blocked(f"ads.{D}", FAMILY_IP))  # and its regex allow rule
    assert client.get("/api/settings/privacy").json()["level"] == 1
    records = client.get("/api/zones", params={"q": "backup-it"}).json()["rows"]
    rid = records[0]["id"]
    assert any(r["type"] == "TXT" and r["value"] == 'say "hi"' for r in client.get(f"/api/zones/{rid}/records").json()["rows"])
    client.put("/api/settings/privacy", json={"level": 0, "retention_hours": 24})


@pytest.fixture
def secondary():
    target = os.environ.get("DNSONE_TEST_SECONDARY")
    if not target:
        pytest.skip("DNSONE_TEST_SECONDARY not set")
    host, _, port = target.rpartition(":")
    return host, int(port)


def _soa_serial(host: str, port: int, zone: str):
    import dns.message
    import dns.query
    import dns.rdatatype
    query = dns.message.make_query(f"{zone}.", dns.rdatatype.SOA)
    query.flags &= ~0x0100
    try:
        response = dns.query.udp(query, host, port=port, timeout=2)
    except Exception:  # noqa: BLE001
        return None
    for rrset in response.answer:
        if rrset.rdtype == dns.rdatatype.SOA:
            return int(rrset[0].serial)
    return None


@needs("api.cluster")
def test_cluster_catalog_and_replica(client, setup, secondary, tmp_path):
    from dnsone import cluster
    from dnsone.config import get_settings
    from dnsone.zonegen import Publisher

    host, port = secondary
    # A new name each run: the secondary outlives the test database.
    name = f"cluster-{int(time.time())}.test"
    zone = client.post("/api/zones", json={"name": name, "soa_rname": f"hostmaster@{name}",
                                            "nameservers": [{"host": "ns1", "address": "192.0.2.53"}]}).json()
    assert client.put("/api/cluster/secondaries", json={"servers": [{"address": "nope"}]}).status_code == 422
    saved = client.put("/api/cluster/secondaries", json={"servers": [{"address": host, "port": port, "name": "ns2"}]})
    assert saved.status_code == 200
    s = get_settings()
    conf = s.bind_zones_conf.read_text()
    assert f'zone "{s.catalog_zone}"' in conf and f"also-notify {{ {host} port {port}; }};" in conf
    catalog = (s.zones_dir / f"{s.catalog_zone}.catalog").read_text()
    assert f"{name}." in catalog and 'version\tIN\tTXT\t"2"' in catalog

    # The secondary learns the zone from the catalog and transfers it.
    serial = client.get(f"/api/zones/{zone['id']}").json()["published_serial"]
    assert eventually(lambda: _soa_serial(host, port, name) == serial, timeout=30, interval=1)
    client.post(f"/api/zones/{zone['id']}/records", json={"name": "www", "type": "A", "value": "192.0.2.9"})
    newer = client.get(f"/api/zones/{zone['id']}").json()["published_serial"]
    assert newer > serial and eventually(lambda: _soa_serial(host, port, name) == newer, timeout=30, interval=1)

    # A replica: never publishes; points its resolver at its own BIND secondary.
    replica = dataclasses.replace(s, role="replica", node_name="replica-it", bind_address=host, bind_port=port, rec_control=["true"],
                                  recursor_forward_zones_file=tmp_path / "forward-zones.conf", recursor_nta_file=tmp_path / "nta.txt",
                                  dnsdist_auth_zones_file=tmp_path / "auth-zones.txt")
    publisher = Publisher(replica)
    assert publisher.publish(zone["id"]).skipped
    ok, message = publisher.replica_sync()
    assert ok, message
    assert f"{name}={host}:{port}" in (tmp_path / "forward-zones.conf").read_text()
    assert json.loads((tmp_path / "zone-serials.json").read_text())[name] == newer
    assert name in (tmp_path / "auth-zones.txt").read_text()

    ok, messages = cluster.sync()
    assert ok, messages
    overview = client.get("/api/cluster").json()
    assert overview["role"] == "primary" and overview["secondaries"][0]["name"] == "ns2" and overview["catalog_serial"]
    node = next(n for n in overview["nodes"] if n["node"] == s.node_name)
    assert not node["stale"] and node["daemons"]["recursor_policy"] == node["policy_serial"]
    text = client.get("/api/cluster/secondary-config", params={"primary": "10.0.0.11"}).text
    assert 'default-primaries { 10.0.0.11 port 5301; }' in text

    # Deleting the zone takes it off the secondary too.
    client.delete(f"/api/zones/{zone['id']}")
    assert eventually(lambda: _soa_serial(host, port, name) is None, timeout=30, interval=1)
    # Removing the secondaries removes the catalog.
    client.put("/api/cluster/secondaries", json={"servers": []})
    assert f'zone "{s.catalog_zone}"' not in s.bind_zones_conf.read_text()
    assert not (s.zones_dir / f"{s.catalog_zone}.catalog").exists()


def test_health_reports_runtime(client, setup):
    checks = {c["name"]: c for c in client.get("/api/system/health").json()["checks"]}
    assert checks["Client policies"]["status"] == "ok", checks["Client policies"]
    assert checks["DNS server settings"]["status"] == "ok", checks["DNS server settings"]
