"""End-to-end tests against real MySQL 8, BIND, PowerDNS Recursor and dnsdist.

Point DNSONE_TEST_ENV at an env file like /etc/dnsone/dnsone.env for a test stack (the database
in DNSONE_DATABASE_URL is replaced by DNSONE_TEST_DATABASE, default dnsone_test, which is dropped and
recreated). Set DNSONE_TEST_DNSDIST to host:port of dnsdist to check answers end to end.
Skipped when DNSONE_TEST_ENV is not set.
"""

from __future__ import annotations

import http.server
import os
import threading
import time
from pathlib import Path

import pytest

from helpers import ENV, PASSWORD, bind_serial, dig

pytestmark = pytest.mark.skipif(not ENV, reason="DNSONE_TEST_ENV not set")


def test_auth_and_csrf(client):
    me = client.get("/api/auth/me").json()
    assert me["user"]["username"] == "admin" and "users.manage" in me["permissions"]
    token = client.headers.pop("X-CSRF-Token")
    try:
        assert client.post("/api/zones", json={}).status_code == 403
    finally:
        client.headers["X-CSRF-Token"] = token
    from fastapi.testclient import TestClient
    anon = TestClient(client.app)
    assert anon.get("/api/zones").status_code == 401
    bad = anon.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    assert bad.status_code == 401 and bad.json()["message"] == "Wrong username or password."


def test_viewer_is_read_only(client):
    from fastapi.testclient import TestClient
    viewer = TestClient(client.app)
    csrf = viewer.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD}).json()["csrf"]
    viewer.headers["X-CSRF-Token"] = csrf
    assert viewer.get("/api/zones").status_code == 200
    assert viewer.post("/api/zones", json={"name": "x.test", "soa_rname": "h@x.test", "nameservers": [{"host": "ns.example.net"}]}).status_code == 403
    assert viewer.get("/api/users").status_code == 403


def test_zone_lifecycle(client):
    body = {"name": "dnsone-it.test", "soa_rname": "hostmaster@dnsone-it.test", "default_ttl": 3600,
            "nameservers": [{"host": "ns1", "address": "192.0.2.53"}, {"host": "ns.example.net"}]}
    missing_glue = client.post("/api/zones", json={**body, "nameservers": [{"host": "ns1"}]})
    assert missing_glue.status_code == 422 and "nameservers.0.address" in missing_glue.json()["errors"]

    created = client.post("/api/zones", json=body)
    assert created.status_code == 201, created.text
    zone = created.json()
    zid = zone["id"]
    # TestClient runs the publish background task before returning.
    zone = client.get(f"/api/zones/{zid}").json()
    assert zone["publish_state"] == "published", zone["last_error"]
    assert bind_serial("dnsone-it.test") == zone["published_serial"]

    assert client.post("/api/zones", json=body).status_code == 409

    www = client.post(f"/api/zones/{zid}/records", json={"name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300})
    assert www.status_code == 201, www.text
    assert client.post(f"/api/zones/{zid}/records", json={"name": "www", "type": "A", "value": "192.0.2.10"}).status_code == 409
    assert client.post(f"/api/zones/{zid}/records", json={"name": "www", "type": "CNAME", "value": "other.example.net"}).json()["errors"].get("type")
    assert client.post(f"/api/zones/{zid}/records", json={"name": "@", "type": "CNAME", "value": "x.example.net"}).status_code == 422
    assert client.post(f"/api/zones/{zid}/records", json={"name": "@", "type": "MX", "value": "mail", "priority": 10}).status_code == 201
    assert client.post(f"/api/zones/{zid}/records", json={"name": "mail", "type": "A", "value": "192.0.2.25"}).status_code == 201
    assert client.post(f"/api/zones/{zid}/records", json={"name": "@", "type": "TXT", "value": "v=spf1 mx -all"}).status_code == 201
    assert client.post(f"/api/zones/{zid}/records", json={"name": "ttl", "type": "A", "value": "192.0.2.1", "ttl": 5}).json()["errors"] == {"ttl": "TTL must be between 60 and 604800 seconds."}

    zone = client.get(f"/api/zones/{zid}").json()
    assert zone["publish_state"] == "published"
    serial = zone["published_serial"]
    assert bind_serial("dnsone-it.test") == serial

    # Through dnsdist -> Recursor -> forward-zones -> BIND.
    answer = dig("www.dnsone-it.test.", "A")
    assert [rr.to_text() for rrset in answer.answer for rr in rrset] == ["192.0.2.10"]

    listed = client.get(f"/api/zones/{zid}/records", params={"type": "A", "size": 2}).json()
    assert listed["total"] == 3 and listed["pages"] == 2 and len(listed["rows"]) == 2
    assert client.get("/api/zones", params={"q": "it.test"}).json()["total"] == 1

    rid = www.json()["id"]
    updated = client.patch(f"/api/zones/{zid}/records/{rid}", json={"value": "192.0.2.11"})
    assert updated.status_code == 200 and updated.json()["value"] == "192.0.2.11"
    assert bind_serial("dnsone-it.test") > serial
    # The Recursor's cache was wiped on publish: clients see the new address immediately.
    answer = dig("www.dnsone-it.test.", "A")
    assert [rr.to_text() for rrset in answer.answer for rr in rrset] == ["192.0.2.11"]

    ns = [r for r in client.get(f"/api/zones/{zid}/records", params={"type": "NS"}).json()["rows"]]
    assert client.delete(f"/api/zones/{zid}/records/{ns[0]['id']}").status_code == 200
    last = client.delete(f"/api/zones/{zid}/records/{ns[1]['id']}")
    assert last.status_code == 422 and "at least one NS" in last.json()["message"]


def test_invalid_zone_keeps_live_file(client):
    zid = client.get("/api/zones", params={"q": "dnsone-it.test"}).json()["rows"][0]["id"]
    before = bind_serial("dnsone-it.test")
    path = Path(os.environ["DNSONE_ZONES_DIR"]) / "dnsone-it.test.zone"
    live = path.read_text()
    # An in-zone name server without an address passes field validation but fails named-checkzone.
    bad = client.post(f"/api/zones/{zid}/records", json={"name": "@", "type": "NS", "value": "ns9"})
    assert bad.status_code == 201
    zone = client.get(f"/api/zones/{zid}").json()
    assert zone["publish_state"] == "error"
    assert "named-checkzone" in zone["last_error"]
    assert path.read_text() == live
    assert bind_serial("dnsone-it.test") == before
    client.delete(f"/api/zones/{zid}/records/{bad.json()['id']}")
    assert client.get(f"/api/zones/{zid}").json()["publish_state"] == "published"


def test_preview_and_disable_and_delete(client):
    zid = client.get("/api/zones", params={"q": "dnsone-it.test"}).json()["rows"][0]["id"]
    preview = client.get(f"/api/zones/{zid}/preview").json()
    assert "$ORIGIN dnsone-it.test." in preview["text"]
    assert client.patch(f"/api/zones/{zid}", json={"soa_retry": 9000}).status_code == 422
    assert client.patch(f"/api/zones/{zid}", json={"status": "disabled"}).status_code == 200
    assert bind_serial("dnsone-it.test") is None
    assert client.patch(f"/api/zones/{zid}", json={"status": "active"}).status_code == 200
    assert bind_serial("dnsone-it.test") is not None
    assert client.delete(f"/api/zones/{zid}").status_code == 200
    assert bind_serial("dnsone-it.test") is None
    assert not (Path(os.environ["DNSONE_ZONES_DIR"]) / "dnsone-it.test.zone").exists()


@pytest.fixture(scope="module")
def blocklist_server():
    body = b"# test list\n0.0.0.0 ads.dnsone-test.example\n0.0.0.0 tracker.dnsone-test.example\n0.0.0.0 keep.dnsone-test.example\n||dnsonetld^\n"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("ETag", '"v1"')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/hosts.txt"
    server.shutdown()


def _rcode(name: str) -> str:
    import dns.rcode
    return dns.rcode.to_text(dig(name, "A").rcode())


def test_rpz_pipeline(client, blocklist_server):
    created = client.post("/api/rpz/blocklists", json={"name": "Test list", "url": blocklist_server})
    assert created.status_code == 201, created.text
    bl = client.get("/api/rpz/blocklists").json()["rows"][0]
    assert bl["last_status"] == "ok" and bl["domain_count"] == 4
    status = client.get("/api/rpz/status").json()["state"]
    assert status["state"] == "ok" and status["entries"] == 8  # 3 names and a whole TLD, each with its wildcard

    # See list: the downloaded domains, searched and paged, and the whole list as a file.
    seen = client.get(f"/api/rpz/blocklists/{bl['id']}/domains", params={"size": 2}).json()
    assert seen["total"] == 4 and seen["pages"] == 2 and len(seen["rows"]) == 2 and seen["list"]["name"] == "Test list"
    assert seen["rows"] == sorted(seen["rows"]) and client.get(f"/api/rpz/blocklists/{bl['id']}/domains", params={"size": 2, "page": 2}).json()["rows"]
    found = client.get(f"/api/rpz/blocklists/{bl['id']}/domains", params={"q": "ADS."}).json()
    assert found["rows"] == ["ads.dnsone-test.example"] and found["total"] == 1
    file = client.get(f"/api/rpz/blocklists/{bl['id']}/domains.txt")
    assert file.status_code == 200 and file.text.count("\n") == 4 and 'filename="Test-list.txt"' in file.headers["content-disposition"]
    assert client.get("/api/rpz/blocklists/999999/domains").status_code == 404

    assert _rcode("ads.dnsone-test.example.") == "NXDOMAIN"
    assert _rcode("sub.ads.dnsone-test.example.") == "NXDOMAIN"

    allow = client.post("/api/rpz/rules", json={"pattern": "keep.dnsone-test.example", "action": "allow"})
    assert allow.status_code == 201
    assert client.get("/api/rpz/lookup", params={"domain": "keep.dnsone-test.example"}).json()["allowed"] is True
    look = client.get("/api/rpz/lookup", params={"domain": "x.tracker.dnsone-test.example"}).json()
    assert look["blocked"] is True and look["blocklists"][0]["match"] == "*.tracker.dnsone-test.example"
    look = client.get("/api/rpz/lookup", params={"domain": "shop.dnsonetld"}).json()
    assert look["blocked"] is True and look["blocklists"][0]["match"] == "*.dnsonetld"

    rpz_text = Path(os.environ["DNSONE_RPZ_FILE"]).read_text()
    assert "keep.dnsone-test.example\tCNAME\trpz-passthru." in Path(os.environ["DNSONE_RPZ_FILE"]).with_name("dnsone-allow.rpz").read_text()
    assert "ads.dnsone-test.example\tCNAME\t." in rpz_text

    policy = client.put("/api/rpz/policy", json={"action": "walled_garden", "walled_garden_target": "192.0.2.80", "block_subdomains": False})
    assert policy.status_code == 200
    answer = dig("ads.dnsone-test.example.", "A")
    assert [rr.to_text() for rrset in answer.answer for rr in rrset] == ["192.0.2.80"]
    # The whole TLD from the list (||dnsonetld^) is in the RPZ the Recursor loaded.
    assert [rr.to_text() for rrset in dig("dnsonetld.", "A").answer for rr in rrset] == ["192.0.2.80"]
    assert "*.ads.dnsone-test.example" not in Path(os.environ["DNSONE_RPZ_FILE"]).read_text()
    assert client.put("/api/rpz/policy", json={"action": "walled_garden", "walled_garden_target": ""}).status_code == 422

    exact = client.post("/api/rpz/rules", json={"pattern": "exact.dnsone-test.example", "action": "block"}).json()
    rpz_text = Path(os.environ["DNSONE_RPZ_FILE"]).read_text()
    assert "exact.dnsone-test.example\tA\t192.0.2.80" in rpz_text
    assert "*.exact.dnsone-test.example" not in rpz_text  # block_subdomains is off now
    client.put("/api/rpz/policy", json={"action": "nxdomain", "block_subdomains": True})
    assert "*.exact.dnsone-test.example\tCNAME\t." in Path(os.environ["DNSONE_RPZ_FILE"]).read_text()
    assert _rcode("x.exact.dnsone-test.example.") == "NXDOMAIN"
    assert client.get("/api/rpz/lookup", params={"domain": "x.exact.dnsone-test.example"}).json()["blocked"] is True
    client.delete(f"/api/rpz/rules/{exact['id']}")

    rule = client.post("/api/rpz/rules", json={"pattern": "*.manual.dnsone-test.example", "action": "nodata"}).json()
    assert client.post("/api/rpz/rules", json={"pattern": "*.manual.dnsone-test.example", "action": "block"}).status_code == 409
    assert client.patch(f"/api/rpz/rules/{rule['id']}", json={"enabled": False}).json()["enabled"] is False
    imported = client.post("/api/rpz/rules/import", json={"action": "block", "text": "one.example\ntwo.example\nnot valid!\none.example"}).json()
    assert imported["added"] == 2 and imported["invalid_count"] == 1
    assert client.get("/api/rpz/rules", params={"action": "block"}).json()["total"] == 2

    build = client.post("/api/rpz/build").json()
    assert build["serial"] == client.get("/api/rpz/status").json()["state"]["serial"]


def test_users_and_audit(client):
    roles = client.get("/api/roles").json()
    operator = next(r for r in roles["roles"] if r["name"] == "operator")
    weak = client.post("/api/users", json={"username": "op1", "role_id": operator["id"], "password": "short"})
    assert weak.status_code == 422 and "password" in weak.json()["errors"]
    created = client.post("/api/users", json={"username": "op1", "name": "Op", "role_id": operator["id"], "password": "operator-password-1"})
    assert created.status_code == 201
    me = client.get("/api/auth/me").json()["user"]
    assert client.patch(f"/api/users/{me['id']}", json={"enabled": False}).status_code == 422
    assert client.delete(f"/api/users/{me['id']}").status_code == 422
    assert client.delete(f"/api/users/{created.json()['id']}").status_code == 200

    log = client.get("/api/audit", params={"entity": "zone"}).json()
    actions = {row["action"] for row in log["rows"]}
    assert {"zone.created", "zone.updated", "zone.deleted"} <= actions
    assert all(row["actor"] == "admin" for row in log["rows"])
    users = client.get("/api/audit", params={"q": "op1"}).json()
    assert any(row["action"] == "user.created" for row in users["rows"])
    assert "password" not in str([r["payload"] for r in users["rows"]]).replace('"password": "***"', "").replace("'password': 'changed'", "")


def test_health_stats_dashboard(client):
    from dnsone import stats
    from dnsone.db import session_scope
    with session_scope() as db:
        stats.collect(db)
    time.sleep(1.1)
    dig("www.example.com.", "A")
    with session_scope() as db:
        stats.collect(db)
    summary = client.get("/api/stats/summary").json()
    assert summary["totals"]["queries"] >= 1
    health = client.get("/api/system/health").json()
    assert {c["name"] for c in health["checks"]} >= {"MySQL", "BIND (rndc)", "PowerDNS Recursor", "dnsdist"}
    assert all(c["status"] == "ok" for c in health["checks"] if c["name"] in ("MySQL", "BIND (rndc)", "PowerDNS Recursor", "dnsdist"))
    assert client.get("/api/health").json()["status"] in ("ok", "warning")
    dash = client.get("/api/dashboard").json()
    assert len(dash["metrics"]) == 8 and dash["recent"] and "traffic" in dash
    # Ten-minute buckets over 24 hours.
    assert len(dash["series"]) == 145 and dash["series"][1]["hour"] > dash["series"][0]["hour"]


def test_logout(client):
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401
