"""End-to-end: encrypted DNS (DoT/DoH through dnsdist), alerts and Prometheus metrics.

Needs the test stack described in test_integration.py. DoT/DoH tests also need dnsdist.conf with
ENCRYPTED_DNS = true and DNSONE_TEST_DOT=host:port, DNSONE_TEST_DOH=https://host:port/dns-query.
"""

from __future__ import annotations

import http.server
import json
import os
import threading
from datetime import timedelta

import pytest

from helpers import ENV

pytestmark = pytest.mark.skipif(not ENV, reason="DNSONE_TEST_ENV not set")


def _encrypted_query(kind: str, name: str):
    import dns.message
    import dns.query
    import httpx

    query = dns.message.make_query(name, "A")
    if kind == "dot":
        target = os.environ.get("DNSONE_TEST_DOT")
        if not target:
            pytest.skip("DNSONE_TEST_DOT not set")
        host, _, port = target.rpartition(":")
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # the test stack's certificate is self-signed
        return dns.query.tls(query, host, port=int(port), timeout=5, ssl_context=context)
    url = os.environ.get("DNSONE_TEST_DOH")
    if not url:
        pytest.skip("DNSONE_TEST_DOH not set")
    response = httpx.post(url, content=query.to_wire(), headers={"content-type": "application/dns-message",
                          "accept": "application/dns-message"}, verify=False, timeout=5)
    response.raise_for_status()
    return dns.message.from_wire(response.content)


def test_encrypted_dns(client):
    zone = client.post("/api/zones", json={"name": "tls-it.test", "soa_rname": "hostmaster@tls-it.test", "nameservers": [{"host": "ns.example.net"}]}).json()
    assert client.post(f"/api/zones/{zone['id']}/records", json={"name": "www", "type": "A", "value": "192.0.2.43"}).status_code == 201
    for kind in ("dot", "doh"):
        answer = _encrypted_query(kind, "www.tls-it.test.")
        assert [rd.to_text() for rrset in answer.answer for rd in rrset] == ["192.0.2.43"], kind
    checks = {c["name"]: c for c in client.get("/api/system/health").json()["checks"]}
    assert checks["Encrypted DNS"]["status"] == "ok" and "DoT" in checks["Encrypted DNS"]["detail"] and "DoH" in checks["Encrypted DNS"]["detail"]


class _Hook(http.server.BaseHTTPRequestHandler):
    received: list[dict] = []
    status = 200

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["content-length"]))
        _Hook.received.append(json.loads(body))
        self.send_response(_Hook.status)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture()
def webhook():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Hook)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _Hook.received.clear()
    _Hook.status = 200
    yield f"http://127.0.0.1:{server.server_address[1]}/hook"
    server.shutdown()


def test_alert_settings(client):
    bad = client.put("/api/settings/alerts", json={"enabled": True, "email": {"enabled": True, "to": []}})
    assert bad.status_code == 422 and "email.to" in bad.json()["errors"]
    assert client.put("/api/settings/alerts", json={"webhook": {"enabled": True, "url": "ftp://x"}}).json()["errors"].get("webhook.url")
    saved = client.put("/api/settings/alerts", json={"enabled": True, "telegram": {"enabled": True, "bot_token": "123:secret-token", "chat_id": "-100"}})
    assert saved.status_code == 200, saved.text
    tg = saved.json()["config"]["telegram"]
    assert tg["bot_token"] == "" and tg["bot_token_set"] is True
    # Saving again without the token keeps it.
    again = client.put("/api/settings/alerts", json={"enabled": True, "telegram": {"enabled": True, "chat_id": "-100"}}).json()
    assert again["config"]["telegram"]["bot_token_set"] is True
    audit = client.get("/api/audit", params={"action": "settings.alerts"}).json()["rows"][0]
    assert "secret-token" not in json.dumps(audit)
    assert client.put("/api/settings/alerts", json={"enabled": False}).status_code == 200


def test_alerts_fire_and_resolve(client, webhook):
    from dnsone import alerts
    from dnsone.db import session_scope
    from dnsone.system import utcnow

    cfg = {"enabled": True, "for_minutes": 2, "repeat_hours": 6, "webhook": {"enabled": True, "url": webhook}}
    assert client.put("/api/settings/alerts", json=cfg).status_code == 200
    test = client.post("/api/settings/alerts/test").json()["results"]
    assert test == {"webhook": "ok"} and _Hook.received[-1]["alerts"][0]["title"] == "Test alert"
    _Hook.received.clear()

    # A blocklist that cannot be downloaded is a problem to report.
    bl = client.post("/api/rpz/blocklists", json={"name": "broken-it", "url": "http://127.0.0.1:9/list.txt"}).json()
    client.post(f"/api/rpz/blocklists/{bl['id']}/refresh")
    t0 = utcnow()
    with session_scope() as db:
        first = alerts.check(db, now=t0)
    key = f"blocklist:{bl['id']}"
    assert key in {a["key"] for a in first["active"]} and key not in first["sent"]
    assert not _Hook.received  # not yet: it has to last for_minutes

    with session_scope() as db:
        later = alerts.check(db, now=t0 + timedelta(minutes=2))
    assert key in later["sent"] and later["delivery"]["results"] == {"webhook": "ok"}
    sent = _Hook.received[-1]
    assert "broken-it" in sent["text"] and any(a["key"] == key and a["state"] == "firing" for a in sent["alerts"])
    assert key in {a["key"] for a in client.get("/api/alerts").json()["active"]}

    with session_scope() as db:
        quiet = alerts.check(db, now=t0 + timedelta(minutes=3))
    assert key not in quiet["sent"]  # already notified; repeats after repeat_hours
    with session_scope() as db:
        repeat = alerts.check(db, now=t0 + timedelta(hours=6, minutes=3))
    assert key in repeat["sent"]

    assert client.delete(f"/api/rpz/blocklists/{bl['id']}").status_code == 200
    _Hook.received.clear()
    with session_scope() as db:
        done = alerts.check(db, now=t0 + timedelta(hours=7))
    assert key in done["resolved"]
    assert any(a["key"] == key and a["state"] == "resolved" for a in _Hook.received[-1]["alerts"])

    # A failing channel is reported, and the alert is tried again on the next run.
    _Hook.status = 500
    with session_scope() as db:
        results = alerts.send_test(db)
    assert results == {"webhook": "failed: HTTP 500"}
    client.put("/api/settings/alerts", json={"enabled": False})


def test_prometheus_metrics(client):
    text = client.get("/api/metrics").text
    assert 'dnsone_info{version="' in text and 'dnsone_health_status{check="MySQL"} 0' in text
    assert 'dnsone_zones{state="published"}' in text and "# TYPE dnsone_dns_events_total counter" in text
    assert 'dnsone_alerts_active{severity="error"}' in text

    # Prometheus scrapes with a read-only app password.
    token = client.post("/api/auth/tokens", json={"name": "prometheus", "read_only": True}).json()["token"]
    from fastapi.testclient import TestClient
    scraper = TestClient(client.app)
    response = scraper.get("/api/metrics", headers={"authorization": f"Bearer {token}"})
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/plain; version=0.0.4")
    assert scraper.get("/api/metrics").status_code == 401
