"""End-to-end tests of DNSOne 1.4: customer and reseller roles, zone templates, zone history and
rollback, ALIAS records, court-ordered blocking, Safe Search, DNS64, query log export (syslog and
dnstap), dynamic DNS (RFC 2136 and dyndns2) and single sign-on with an OpenID Connect provider.

Same test stack as test_features.py. dnsone-ddns and dnsone-querylog run as subprocesses; the
OpenID provider, the syslog collector and the dnstap receiver are small servers in this file.
Safe Search and ALIAS to an outside name need the test Recursor and the system resolver to reach
the internet.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest

from helpers import ENV, PASSWORD, bind_serial, eventually, needs

pytestmark = pytest.mark.skipif(not ENV or not os.environ.get("DNSONE_TEST_DNSDIST"), reason="DNSONE_TEST_ENV / DNSONE_TEST_DNSDIST not set")

DEFAULT_IP, FAMILY_IP, OPEN_IP, OTHER_IP = "127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"
D = "isp-it.test"


def ask(name: str, source: str = DEFAULT_IP, rtype: str = "A"):
    import dns.message
    import dns.query
    import dns.rdatatype
    host, _, port = os.environ["DNSONE_TEST_DNSDIST"].rpartition(":")
    query = dns.message.make_query(name, getattr(dns.rdatatype, rtype), use_edns=0)
    return dns.query.udp(query, host, port=int(port), timeout=8, source=source)


def values(response, rtype: str) -> list[str]:
    import dns.rdatatype
    return sorted(rd.to_text() for rrset in response.answer if rrset.rdtype == getattr(dns.rdatatype, rtype) for rd in rrset)


def ede(response) -> set[int]:
    import dns.edns
    return {o.code for o in response.options if isinstance(o, dns.edns.EDEOption)}


def bind_answer(name: str, rtype: str = "A") -> list[str]:
    import dns.message
    import dns.query
    import dns.rdatatype
    host, port = os.environ["DNSONE_BIND_ADDRESS"], int(os.environ["DNSONE_BIND_PORT"])
    query = dns.message.make_query(name, getattr(dns.rdatatype, rtype))
    response = dns.query.udp(query, host, port=port, timeout=3)
    return values(response, rtype)


def login(client, username: str, password: str = PASSWORD):
    from fastapi.testclient import TestClient
    other = TestClient(client.app)
    response = other.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    other.headers["X-CSRF-Token"] = response.json()["csrf"]
    return other


def published(client, zone_id: int) -> dict:
    zone = eventually(lambda: (lambda z: z if z["publish_state"] == "published" and not z["pending"] else None)(client.get(f"/api/zones/{zone_id}").json()), timeout=20)
    assert zone, client.get(f"/api/zones/{zone_id}").json()
    return zone


def make_zone(client, name: str, records: list[dict] = ()) -> dict:
    created = client.post("/api/zones", json={"name": name, "soa_rname": f"hostmaster@{name}",
                                              "nameservers": [{"host": f"ns1.{name}", "address": "192.0.2.53"}]})
    assert created.status_code == 201, created.text
    zone = created.json()
    for r in records:
        response = client.post(f"/api/zones/{zone['id']}/records", json=r)
        assert response.status_code == 201, response.text
    return published(client, zone["id"])


def role_id(client, name: str) -> int:
    return next(r["id"] for r in client.get("/api/roles").json()["roles"] if r["name"] == name)


@pytest.fixture(scope="module")
def isp(client):
    zone = make_zone(client, D, [
        {"name": "www", "type": "A", "value": "192.0.2.10"},
        {"name": "v4only", "type": "A", "value": "192.0.2.20"},
        {"name": "target", "type": "A", "value": "192.0.2.30"},
        {"name": "blocked", "type": "A", "value": "192.0.2.40"},
        {"name": "x.wild", "type": "A", "value": "192.0.2.41"},
        {"name": "wild", "type": "A", "value": "192.0.2.42"},
    ])
    family = client.post("/api/groups", json={"name": "Family"}).json()
    open_ = client.post("/api/groups", json={"name": "Open", "blocking": False}).json()
    assert client.post(f"/api/groups/{family['id']}/networks", json={"network": "127.0.0.2/31"}).status_code == 201
    assert client.post(f"/api/groups/{open_['id']}/networks", json={"network": OPEN_IP}).status_code == 201
    return {"zone": zone, "family": family, "open": open_}


# --------------------------------------------------------------------------- roles and self-service


@needs("quota")
def test_customer_and_reseller_scope(client, isp):
    cust_a = make_zone(client, "cust-a.test")
    # Roles limited to their own zones hold zone permissions only.
    bad = client.post("/api/roles", json={"name": "bad", "permissions": ["zones.view", "rpz.view"], "zone_scope": "assigned"})
    assert bad.status_code == 422 and "rpz.view" in bad.json()["message"]
    assert client.patch(f"/api/roles/{role_id(client, 'customer')}", json={"permissions": ["zones.view"]}).status_code == 422
    auditor = client.post("/api/roles", json={"name": "dns-auditor", "permissions": ["zones.view", "audit.view"]})
    assert auditor.status_code == 201 and auditor.json()["zone_scope"] == "all"

    assert client.post("/api/users", json={"username": "reseller1", "role_id": role_id(client, "reseller"), "password": PASSWORD}).status_code == 201
    reseller = login(client, "reseller1")
    assert reseller.get("/api/zones").json()["total"] == 0
    assert reseller.get(f"/api/zones/{cust_a['id']}").status_code == 404
    resold = reseller.post("/api/zones", json={"name": "resold.test", "soa_rname": "hostmaster@resold.test", "nameservers": [{"host": "ns1.example.net"}]})
    assert resold.status_code == 201, resold.text
    resold = resold.json()
    assert [z["name"] for z in reseller.get("/api/zones").json()["rows"]] == ["resold.test"]
    assert [r["name"] for r in reseller.get("/api/roles").json()["roles"]] == ["customer"]

    # A reseller gives its customers only its own zones, and sees only its own customers.
    nope = reseller.post("/api/users", json={"username": "cust1", "role_id": role_id(client, "customer"), "password": PASSWORD, "zone_ids": [cust_a["id"]]})
    assert nope.status_code == 422
    customer = reseller.post("/api/users", json={"username": "cust1", "role_id": role_id(client, "customer"), "password": PASSWORD, "zone_ids": [resold["id"]]})
    assert customer.status_code == 201, customer.text
    customer = customer.json()
    assert customer["zones"] == 1 and customer["parent_id"] is not None
    assert reseller.post("/api/users", json={"username": "op2", "role_id": role_id(client, "admin"), "password": PASSWORD}).status_code == 422
    assert [u["username"] for u in reseller.get("/api/users").json()["rows"]] == ["cust1"]
    admin_id = next(u["id"] for u in client.get("/api/users").json()["rows"] if u["username"] == "admin")
    assert reseller.patch(f"/api/users/{admin_id}", json={"name": "x"}).status_code == 404

    cust = login(client, "cust1")
    assert cust.get("/api/auth/me").json()["user"]["zone_scope"] == "assigned"
    assert [z["name"] for z in cust.get("/api/zones").json()["rows"]] == ["resold.test"]
    assert cust.post(f"/api/zones/{resold['id']}/records", json={"name": "www", "type": "A", "value": "192.0.2.90"}).status_code == 201
    assert cust.delete(f"/api/zones/{resold['id']}").status_code == 403
    assert cust.post("/api/zones", json={"name": "mine.test", "soa_rname": "h@mine.test", "nameservers": [{"host": "ns1.example.net"}]}).status_code == 403
    assert cust.get(f"/api/zones/{cust_a['id']}/records").status_code == 404
    assert cust.get("/api/rpz/status").status_code == 403
    assert cust.get("/api/users").status_code == 403

    # Administrators give any zone; the customer then sees it.
    assert client.put(f"/api/users/{customer['id']}/zones", json={"zone_ids": [resold["id"], cust_a["id"]]}).status_code == 200
    assert cust.get("/api/zones").json()["total"] == 2
    assert reseller.get("/api/zones").json()["total"] == 1
    # Every zone already for roles with zone scope "all".
    op = client.post("/api/users", json={"username": "op1", "role_id": role_id(client, "operator"), "password": PASSWORD}).json()
    assert client.put(f"/api/users/{op['id']}/zones", json={"zone_ids": [cust_a["id"]]}).status_code == 422
    assert client.delete(f"/api/roles/{auditor.json()['id']}").status_code == 200
    assert published(client, resold["id"])


# --------------------------------------------------------------------------- templates


def test_zone_templates(client, isp):
    undeclared = client.post("/api/templates", json={"name": "bad", "records": [{"name": "@", "type": "A", "value": "{ip}"}]})
    assert undeclared.status_code == 422 and "ip" in undeclared.json()["message"]
    invalid = client.post("/api/templates", json={"name": "bad", "records": [{"name": "@", "type": "A", "value": "not-an-ip"}]})
    assert invalid.status_code == 422
    template = client.post("/api/templates", json={
        "name": "Web hosting", "description": "Site and mail", "soa_rname": "hostmaster@{zone}",
        "nameservers": [{"host": "ns1.isp.example"}, {"host": "ns2.isp.example"}],
        "variables": [{"name": "ip", "label": "Web server address"}, {"name": "mx", "label": "Mail host", "default": "mail.isp.example"}],
        "records": [
            {"name": "@", "type": "A", "value": "{ip}"},
            {"name": "www", "type": "CNAME", "value": "@"},
            {"name": "@", "type": "MX", "value": "{mx}", "priority": 10},
            {"name": "@", "type": "TXT", "value": "v=spf1 mx -all"},
            {"name": "_dmarc", "type": "TXT", "value": "v=DMARC1; p=none; rua=mailto:dmarc@{zone}"},
        ],
    })
    assert template.status_code == 201, template.text
    tid = template.json()["id"]

    missing = client.post("/api/zones", json={"name": "tpl-it.test", "soa_rname": "h@tpl-it.test", "nameservers": [{"host": "ns1.example.net"}], "template_id": tid})
    assert missing.status_code == 422 and missing.json()["errors"].get("variables.ip")
    created = client.post("/api/zones", json={"name": "tpl-it.test", "soa_rname": "hostmaster@tpl-it.test",
                                              "nameservers": [{"host": "ns1.example.net"}], "template_id": tid, "variables": {"ip": "192.0.2.80"}})
    assert created.status_code == 201, created.text
    zone = published(client, created.json()["id"])
    assert zone["record_count"] == 6
    assert bind_answer("tpl-it.test.") == ["192.0.2.80"]
    assert bind_answer("tpl-it.test.", "MX") == ["10 mail.isp.example."]
    assert bind_answer("_dmarc.tpl-it.test.", "TXT") == ['"v=DMARC1; p=none; rua=mailto:dmarc@tpl-it.test"']

    # Applied to a zone that has some of it already: the rest is added, conflicts are skipped.
    dry = client.post(f"/api/zones/{isp['zone']['id']}/template", json={"template_id": tid, "variables": {"ip": "192.0.2.10"}, "dry_run": True}).json()
    # www already has an A record there: the template's www CNAME cannot join it.
    assert dry["added"] == 4 and len(dry["skipped"]) == 1 and dry["skipped"][0].startswith("www CNAME")
    client.post(f"/api/zones/{isp['zone']['id']}/records", json={"name": "_dmarc", "type": "CNAME", "value": "dmarc.example.net"})
    applied = client.post(f"/api/zones/{isp['zone']['id']}/template", json={"template_id": tid, "variables": {"ip": "192.0.2.10"}}).json()
    assert applied["added"] == 3 and len(applied["skipped"]) == 2 and any(x.startswith("_dmarc TXT") for x in applied["skipped"])
    again = client.post(f"/api/zones/{isp['zone']['id']}/template", json={"template_id": tid, "variables": {"ip": "192.0.2.10"}}).json()
    assert again["added"] == 0
    published(client, isp["zone"]["id"])


# --------------------------------------------------------------------------- history


def test_zone_history_and_rollback(client, isp):
    zid = client.get("/api/zones", params={"q": "tpl-it"}).json()["rows"][0]["id"]
    first = client.get(f"/api/zones/{zid}/versions").json()
    assert first["total"] == 1 and first["rows"][0]["changes"].get("first")
    base_id = first["rows"][0]["id"]

    client.post(f"/api/zones/{zid}/records", json={"name": "extra", "type": "A", "value": "192.0.2.81"})
    published(client, zid)
    client.patch(f"/api/zones/{zid}", json={"default_ttl": 1800})
    published(client, zid)
    assert bind_answer("extra.tpl-it.test.") == ["192.0.2.81"]
    versions = client.get(f"/api/zones/{zid}/versions").json()["rows"]
    assert len(versions) == 3 and versions[1]["changes"]["added"] == 1 and "admin" in versions[1]["actors"]
    assert versions[0]["changes"]["settings"] == ["default_ttl"]

    detail = client.get(f"/api/zones/{zid}/versions/{versions[1]['id']}").json()
    assert [r["name"] for r in detail["diff"]["added"]] == ["extra"]
    back = client.get(f"/api/zones/{zid}/versions/{base_id}").json()
    assert back["rollback"]["summary"]["removed"] == 1 and back["rollback"]["summary"]["settings"] == ["default_ttl"]

    restored = client.post(f"/api/zones/{zid}/versions/{base_id}/restore")
    assert restored.status_code == 200 and restored.json()["summary"]["removed"] == 1
    zone = published(client, zid)
    assert zone["default_ttl"] == 3600 and bind_answer("extra.tpl-it.test.") == []
    assert client.get(f"/api/zones/{zid}/versions").json()["total"] == 4
    assert client.post(f"/api/zones/{zid}/versions/{base_id}/restore").json()["summary"] == {"added": 0, "removed": 0, "changed": 0, "settings": []}
    log = client.get("/api/audit", params={"action": "zone.rolled"}).json()
    assert any(r["action"] == "zone.rolled_back" for r in log["rows"])


# --------------------------------------------------------------------------- ALIAS


def test_alias_records(client, isp):
    from dnsone import zonegen
    from dnsone.config import get_settings
    from dnsone.db import session_scope
    from dnsone.models import Record, Zone
    zid = isp["zone"]["id"]
    # The template put an A record at the apex: an ALIAS cannot share its name with it.
    apex_a = [r for r in client.get(f"/api/zones/{zid}/records", params={"type": "A"}).json()["rows"] if r["name"] == "@"]
    assert apex_a and client.post(f"/api/zones/{zid}/records", json={"name": "@", "type": "ALIAS", "value": "target"}).status_code == 422
    for r in apex_a:
        client.delete(f"/api/zones/{zid}/records/{r['id']}")
    alias = client.post(f"/api/zones/{zid}/records", json={"name": "@", "type": "ALIAS", "value": "target"})
    assert alias.status_code == 201, alias.text
    published(client, zid)
    assert bind_answer(f"{D}.") == ["192.0.2.30"]
    conflict = client.post(f"/api/zones/{zid}/records", json={"name": "@", "type": "A", "value": "192.0.2.1"})
    assert conflict.status_code == 422 and "ALIAS" in conflict.json()["message"]
    assert client.post(f"/api/zones/{zid}/records", json={"name": "self", "type": "ALIAS", "value": "self"}).status_code == 422

    # A target in another hosted zone: the reconcile timer notices its new address and republishes.
    tpl = client.get("/api/zones", params={"q": "tpl-it"}).json()["rows"][0]["id"]
    assert client.post(f"/api/zones/{tpl}/records", json={"name": "shop", "type": "ALIAS", "value": f"target.{D}"}).status_code == 201
    published(client, tpl)
    assert bind_answer("shop.tpl-it.test.") == ["192.0.2.30"]
    target = next(r for r in client.get(f"/api/zones/{zid}/records", params={"q": "target"}).json()["rows"] if r["name"] == "target")
    client.patch(f"/api/zones/{zid}/records/{target['id']}", json={"value": "192.0.2.31"})
    published(client, zid)
    assert bind_answer(f"{D}.") == ["192.0.2.31"]       # same zone: republished with the change
    assert bind_answer("shop.tpl-it.test.") == ["192.0.2.30"]
    zonegen.Publisher().reconcile()
    assert bind_answer("shop.tpl-it.test.") == ["192.0.2.31"]

    # Outside the hosted zones, through the resolver; an unreachable resolver keeps the last answer.
    assert client.post(f"/api/zones/{tpl}/records", json={"name": "ext", "type": "ALIAS", "value": "www.google.com."}).status_code == 201
    published(client, tpl)
    google = bind_answer("ext.tpl-it.test.")
    assert google
    import dataclasses
    broken = dataclasses.replace(get_settings(), alias_resolvers=("192.0.2.1",))
    with session_scope() as db:
        zone = db.get(Zone, tpl)
        rows = list(db.query(Record).filter(Record.zone_id == tpl))
        answers, warnings = zonegen.resolve_aliases(db, zone, rows, broken)
    assert answers["www.google.com."]["A"] == sorted(google) and any("last addresses are kept" in w for w in warnings)
    # The zone file shows what each ALIAS became.
    preview = client.get(f"/api/zones/{tpl}/preview").json()["text"]
    assert "; ALIAS shop -> target.isp-it.test." in preview and "shop\t" in preview


# --------------------------------------------------------------------------- court orders, Safe Search, DNS64


@needs("legal")
def test_court_ordered_blocking(client, isp):
    viewer = login(client, "viewer")
    assert viewer.get("/api/legal").status_code == 403
    assert client.put("/api/legal/page", json={"address4": "2001:db8::1", "title": "t", "message": "m"}).status_code == 422
    page = client.put("/api/legal/page", json={"address4": "192.0.2.99", "address6": "2001:db8::99", "title": "Blocked by court order",
                                                "message": "This site is blocked by order of the court.", "show_reference": True})
    assert page.status_code == 200
    order = client.post("/api/legal", json={"patterns": f"blocked.{D}\n*.wild.{D}\nnot a domain", "authority": "Court of Tirana", "reference": "123/2026"})
    assert order.status_code == 422
    order = client.post("/api/legal", json={"patterns": f"blocked.{D}\n*.wild.{D}\n# comment", "authority": "Court of Tirana",
                                            "reference": "123/2026", "ordered_on": "2026-10-01"})
    assert order.status_code == 201 and order.json()["added"] == 2
    assert client.post("/api/legal", json={"patterns": f"BLOCKED.{D}.", "authority": "x", "reference": "y"}).json()["already_blocked"] == [f"blocked.{D}"]

    # Not undone by an allow rule, a pause, or a group without blocking.
    assert client.post("/api/rpz/rules", json={"pattern": f"blocked.{D}", "action": "allow"}).status_code == 201
    client.post("/api/rpz/pause", json={"minutes": 10})
    for source in (DEFAULT_IP, FAMILY_IP, OPEN_IP, OTHER_IP):
        response = eventually(lambda: (lambda r: r if values(r, "A") == ["192.0.2.99"] else None)(ask(f"blocked.{D}", source)), timeout=15)
        assert response, (source, ask(f"blocked.{D}", source))
        assert 16 in ede(response)
        assert values(ask(f"sub.blocked.{D}", source), "A") == ["192.0.2.99"]
    assert values(ask(f"blocked.{D}", OTHER_IP, "AAAA"), "AAAA") == ["2001:db8::99"]
    assert values(ask(f"x.wild.{D}", OTHER_IP), "A") == ["192.0.2.99"]
    assert values(ask(f"wild.{D}", OTHER_IP), "A") == ["192.0.2.42"]    # *. covers only the names below
    client.delete("/api/rpz/pause")
    lookup = client.get("/api/rpz/lookup", params={"domain": f"sub.blocked.{D}"}).json()
    assert lookup["blocked"] and lookup["legal"]["reference"] == "123/2026"

    notice = client.get("/api/legal/notice", headers={"Host": f"sub.blocked.{D}"})
    assert notice.status_code == 451 and "123/2026" in notice.text and "Court of Tirana" in notice.text and "<script" not in notice.text
    csv_text = client.get("/api/legal/export").text
    assert f"blocked.{D},active,Court of Tirana,123/2026,2026-10-01" in csv_text

    entry = next(b for b in client.get("/api/legal").json()["rows"] if b["pattern"] == f"blocked.{D}")
    assert client.post(f"/api/legal/{entry['id']}/lift", json={"reason": "x"}).status_code == 422
    lifted = client.post("/api/legal/lift-order", json={"reference": "123/2026", "reason": "Order revoked on appeal"})
    assert lifted.json()["lifted"] == 2
    assert eventually(lambda: values(ask(f"blocked.{D}", OTHER_IP), "A") == ["192.0.2.40"], timeout=15)
    history = client.get("/api/legal", params={"status": "lifted"}).json()
    assert history["total"] == 2 and history["rows"][0]["lift_reason"] == "Order revoked on appeal"
    # Lifted entries stay; the name can be ordered blocked again.
    again = client.post("/api/legal", json={"patterns": f"blocked.{D}", "authority": "Regulator", "reference": "R-9"})
    assert again.json()["added"] == 1
    actions = {r["action"] for r in client.get("/api/audit", params={"entity": "legal_block"}).json()["rows"]}
    assert {"legal_block.added", "legal_block.order_lifted", "legal_block.exported"} <= actions


def test_safe_search_and_dns64(client, isp):
    family = isp["family"]
    reverse = make_zone(client, "2.0.192.in-addr.arpa", [{"name": "20", "type": "PTR", "value": f"v4only.{D}."}])
    assert reverse
    assert client.patch(f"/api/groups/{family['id']}", json={"safe_search": True, "youtube": "strict", "dns64": True}).status_code == 200

    def cname(name, source):
        return values(ask(name, source), "CNAME")

    assert eventually(lambda: cname("www.google.com", FAMILY_IP) == ["forcesafesearch.google.com."], timeout=15)
    assert values(ask("www.google.com", FAMILY_IP), "A") == ["216.239.38.120"]
    assert cname("www.google.co.uk", FAMILY_IP) == ["forcesafesearch.google.com."]
    # The rewrite starts the CNAME chain (the engines' own names may be CNAMEs to their CDN).
    assert "strict.bing.com." in cname("www.bing.com", FAMILY_IP)
    assert "restrict.youtube.com." in cname("www.youtube.com", FAMILY_IP)
    assert "forcesafesearch.google.com." not in cname("www.google.com", OTHER_IP)
    # Paused blocking does not pause Safe Search.
    client.post("/api/rpz/pause", json={"minutes": 5, "group_id": family["id"]})
    time.sleep(2)
    assert cname("www.google.com", FAMILY_IP) == ["forcesafesearch.google.com."]
    client.delete("/api/rpz/pause", params={"group_id": family["id"]})

    # DNS64: AAAA made from the A record under 64:ff9b::/96 for the group; nothing for others.
    assert eventually(lambda: values(ask(f"v4only.{D}", FAMILY_IP, "AAAA"), "AAAA") == ["64:ff9b::c000:214"], timeout=15)
    assert values(ask(f"v4only.{D}", OTHER_IP, "AAAA"), "AAAA") == []
    import dns.reversename
    ptr = dns.reversename.from_address("64:ff9b::c000:214").to_text()
    assert values(ask(ptr, FAMILY_IP, "PTR"), "PTR") == [f"v4only.{D}."]
    server = client.get("/api/settings/dns-server").json()
    body = {k: server[k] for k in ("nat_addresses", "client_qps", "client_burst", "nat_qps", "nat_burst", "public_authoritative", "ddns")}
    body["client_networks"] = server["client_networks"] or ["10.0.0.0/8"]   # loopback is always a customer
    assert client.put("/api/settings/dns-server", json={**body, "dns64_prefix": "2001:db8::/64"}).status_code == 422
    assert client.put("/api/settings/dns-server", json={**body, "dns64_prefix": "2001:db8:64::/96"}).status_code == 200
    assert eventually(lambda: values(ask(f"v4only.{D}", FAMILY_IP, "AAAA"), "AAAA") == ["2001:db8:64::c000:214"], timeout=15)
    client.put("/api/settings/dns-server", json={**body, "dns64_prefix": "64:ff9b::/96"})
    assert client.patch(f"/api/groups/{family['id']}", json={"dns64": False}).status_code == 200
    assert eventually(lambda: values(ask(f"v4only.{D}", FAMILY_IP, "AAAA"), "AAAA") == [], timeout=15)


# --------------------------------------------------------------------------- query log: legal status and export


@pytest.fixture(scope="module")
def collector():
    env = {**os.environ, "DNSONE_ENV_FILE": "/nonexistent"}
    proc = subprocess.Popen([sys.executable, "-c", "import sys; from dnsone.querylog import main; sys.exit(main())"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    host, _, port = os.environ["DNSONE_QUERYLOG_LISTEN"].rpartition(":")

    def listening():
        with socket.socket() as s:
            return s.connect_ex((host, int(port))) == 0

    assert eventually(listening, timeout=10)
    time.sleep(3)
    yield proc
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=20)


@needs("legal", "logexport")
def test_query_log_legal_status_and_syslog_export(client, isp, collector):
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind(("127.0.0.1", 0))
    sink.settimeout(1)
    port = sink.getsockname()[1]
    assert client.put("/api/settings/export", json={"syslog": {"enabled": True, "host": "", "port": port}}).status_code == 422
    saved = client.put("/api/settings/export", json={"syslog": {"enabled": True, "host": "127.0.0.1", "port": port, "format": "json", "facility": "local5"}})
    assert saved.status_code == 200, saved.text
    time.sleep(17)  # dnsone-querylog re-reads the settings every 15 s

    fresh = f"fresh-{int(time.time())}.{D}"
    ask(f"blocked.{D}", OTHER_IP)
    ask(fresh, OTHER_IP)
    received = []
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not any(f"blocked.{D}" in m for m in received):
        try:
            received.append(sink.recv(65535).decode())
        except socket.timeout:
            pass
    sink.close()
    line = next(m for m in received if f"blocked.{D}" in m)
    assert line.startswith("<173>1 ")      # local5 (21) * 8 + notice (5)
    payload = json.loads(line.split(" - query - ", 1)[1])
    assert payload["status"] == "legal" and payload["client"] == OTHER_IP and payload["group"] == "Default"

    def status(qname):
        rows = client.get("/api/queries", params={"limit": 50, "client": OTHER_IP, "qname": qname}).json()["rows"]
        return rows[0]["status"] if rows else None

    assert eventually(lambda: status(f"blocked.{D}") == "legal", timeout=8)
    assert eventually(lambda: status(fresh) == "ok", timeout=8)
    assert client.get("/api/queries", params={"status": "legal"}).status_code == 200
    states = client.get("/api/settings/export").json()["nodes"]
    assert eventually(lambda: any((n.get("export") or {}).get("sent") for n in client.get("/api/settings/export").json()["nodes"]), timeout=70), states
    client.put("/api/settings/export", json={"syslog": {"enabled": False}})


class FrameStreamReceiver:
    """A dnstap collector: Frame Streams over TCP (bidirectional handshake), keeping the data frames."""

    def __init__(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]
        self.frames: list[bytes] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _read(conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise ConnectionError
            data += chunk
        return data

    def _serve(self, conn):
        try:
            while True:
                (length,) = struct.unpack("!I", self._read(conn, 4))
                if length:
                    self.frames.append(self._read(conn, length))
                    continue
                (clen,) = struct.unpack("!I", self._read(conn, 4))
                control = self._read(conn, clen)
                (ctype,) = struct.unpack("!I", control[:4])
                if ctype == 0x04:  # READY -> ACCEPT with the same content type
                    reply = struct.pack("!I", 0x01) + control[4:]
                    conn.sendall(struct.pack("!II", 0, len(reply)) + reply)
                elif ctype == 0x03:  # STOP -> FINISH
                    conn.sendall(struct.pack("!III", 0, 4, 0x05))
                    return
        except (ConnectionError, OSError, struct.error):
            pass


@needs("logexport")
def test_dnstap_export(client, isp):
    receiver = FrameStreamReceiver()
    assert client.put("/api/settings/export", json={"dnstap": {"enabled": True, "target": "not-an-address"}}).status_code == 422
    saved = client.put("/api/settings/export", json={"dnstap": {"enabled": True, "target": f"127.0.0.1:{receiver.port}", "queries": True, "responses": True}})
    assert saved.status_code == 200, saved.text
    time.sleep(4)  # dnsdist re-reads its settings every 2 s
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and b"isp-it" not in b"".join(receiver.frames):
        ask(f"www.{D}", OTHER_IP)
        time.sleep(1)
    joined = b"".join(receiver.frames)
    assert b"isp-it" in joined, receiver.frames[:3]
    assert client.put("/api/settings/export", json={"dnstap": {"enabled": False}}).status_code == 200


# --------------------------------------------------------------------------- dynamic DNS


@pytest.fixture(scope="module")
def ddns_server(client):
    env = {**os.environ, "DNSONE_ENV_FILE": "/nonexistent"}
    proc = subprocess.Popen([sys.executable, "-c", "import sys; from dnsone.ddns import main; sys.exit(main())"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    host, _, port = os.environ["DNSONE_DDNS_LISTEN"].rpartition(":")

    def listening():
        with socket.socket() as s:
            return s.connect_ex((host, int(port))) == 0

    assert eventually(listening, timeout=10)

    def dnsdist_sees_it():
        import httpx
        servers = httpx.get(f"{os.environ['DNSONE_DNSDIST_API_URL']}/api/v1/servers/localhost",
                            headers={"X-API-Key": os.environ["DNSONE_DNSDIST_API_KEY"]}, timeout=3).json()["servers"]
        return any(x["name"] == "ddns" and x["state"].lower() == "up" for x in servers)

    # dnsdist health-checks the backend every 5 s; until then it answers updates itself (SERVFAIL).
    assert eventually(dnsdist_sees_it, timeout=20, interval=1)
    yield proc
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=20)


def _send(update, source=OTHER_IP, tcp=False):
    import dns.query
    host, _, port = os.environ["DNSONE_TEST_DNSDIST"].rpartition(":")
    send = dns.query.tcp if tcp else dns.query.udp
    return send(update, host, port=int(port), timeout=8, source=source)


def test_dynamic_dns(client, isp, ddns_server):
    import dns.rcode
    import dns.tsig
    import dns.update
    zid = isp["zone"]["id"]
    server = client.get("/api/settings/dns-server").json()
    body = {k: server[k] for k in ("nat_addresses", "client_qps", "client_burst", "nat_qps", "nat_burst", "public_authoritative", "dns64_prefix")}
    body["client_networks"] = server["client_networks"] or ["10.0.0.0/8"]
    assert client.put("/api/settings/dns-server", json={**body, "ddns": "everyone"}).status_code == 200
    bad = client.post(f"/api/zones/{zid}/ddns-keys", json={"name": "router", "names": ["home"], "types": ["SOA"]})
    assert bad.status_code == 422
    key = client.post(f"/api/zones/{zid}/ddns-keys", json={"name": "router", "names": ["home", "_acme-challenge", "*.dyn"], "types": ["A", "AAAA", "TXT"]})
    assert key.status_code == 201, key.text
    key = key.json()
    assert key["name"] == f"router.{D}." and key["secret"]
    assert "secret" not in client.get(f"/api/zones/{zid}/ddns-keys").json()["rows"][0]
    keyring = dns.tsig.Key(key["name"], key["secret"], dns.tsig.HMAC_SHA256)
    time.sleep(3)  # dnsdist picks up the routing within 2 s

    up = dns.update.UpdateMessage(f"{D}.", keyring=keyring)
    up.replace("home", 120, "A", "198.51.100.7")
    up.add("_acme-challenge", 60, "TXT", "token-123")
    up.add("a.b.dyn", 60, "AAAA", "2001:db8::7")
    response = _send(up)
    assert response.rcode() == dns.rcode.NOERROR, dns.rcode.to_text(response.rcode())
    assert response.had_tsig
    assert eventually(lambda: bind_answer(f"home.{D}.") == ["198.51.100.7"], timeout=20)
    assert bind_answer(f"_acme-challenge.{D}.", "TXT") == ['"token-123"']
    assert bind_answer(f"a.b.dyn.{D}.", "AAAA") == ["2001:db8::7"]

    # Over TCP too; prerequisites (RFC 2136 3.2) decide.
    up = dns.update.UpdateMessage(f"{D}.", keyring=keyring)
    up.present("home", "A", "203.0.113.1")
    up.replace("home", 120, "A", "198.51.100.8")
    assert _send(up, tcp=True).rcode() == dns.rcode.NXRRSET
    up = dns.update.UpdateMessage(f"{D}.", keyring=keyring)
    up.present("home", "A", "198.51.100.7")
    up.replace("home", 120, "A", "198.51.100.8")
    assert _send(up, tcp=True).rcode() == dns.rcode.NOERROR
    assert eventually(lambda: bind_answer(f"home.{D}.") == ["198.51.100.8"], timeout=20), (
        bind_answer(f"home.{D}."), client.get(f"/api/zones/{zid}/records", params={"q": "home"}).json()["rows"], client.get(f"/api/zones/{zid}").json())

    # Only the names and types the key lists; the whole update is refused otherwise.
    up = dns.update.UpdateMessage(f"{D}.", keyring=keyring)
    up.replace("home", 120, "A", "198.51.100.9")
    up.replace("www", 120, "A", "198.51.100.9")
    assert _send(up).rcode() == dns.rcode.REFUSED
    up = dns.update.UpdateMessage(f"{D}.", keyring=keyring)
    up.add("home", 60, "MX", "10 mail.example.net.")
    assert _send(up).rcode() == dns.rcode.REFUSED
    wrong = dns.update.UpdateMessage(f"{D}.", keyring=dns.tsig.Key(key["name"], base64.b64encode(b"x" * 32).decode(), dns.tsig.HMAC_SHA256))
    wrong.replace("home", 60, "A", "198.51.100.66")
    with pytest.raises(dns.tsig.PeerBadSignature):      # NOTAUTH with TSIG error BADSIG (RFC 8945)
        _send(wrong)
    unknown = dns.update.UpdateMessage(f"{D}.", keyring=dns.tsig.Key(f"nobody.{D}.", key["secret"], dns.tsig.HMAC_SHA256))
    unknown.replace("home", 60, "A", "198.51.100.66")
    with pytest.raises(dns.tsig.PeerBadKey):
        _send(unknown)
    unsigned = dns.update.UpdateMessage(f"{D}.")
    unsigned.replace("home", 60, "A", "198.51.100.66")
    assert _send(unsigned).rcode() == dns.rcode.REFUSED
    other_zone = dns.update.UpdateMessage("tpl-it.test.", keyring=keyring)
    other_zone.replace("home", 60, "A", "198.51.100.66")
    assert _send(other_zone).rcode() == dns.rcode.NOTAUTH
    assert bind_answer(f"home.{D}.") == ["198.51.100.8"] and bind_answer(f"www.{D}.") == ["192.0.2.10"]

    # Delete all records at a name (only the types the key may change).
    up = dns.update.UpdateMessage(f"{D}.", keyring=keyring)
    up.delete("_acme-challenge")
    assert _send(up).rcode() == dns.rcode.NOERROR
    assert eventually(lambda: bind_answer(f"_acme-challenge.{D}.", "TXT") == [], timeout=20)

    # dyndns2: routers' /nic/update with the key name and secret.
    auth = "Basic " + base64.b64encode(f"router:{key['secret']}".encode()).decode()
    from fastapi.testclient import TestClient
    anon = TestClient(client.app)
    answer = anon.get("/api/ddns/nic/update", params={"hostname": f"home.{D}", "myip": "198.51.100.20"}, headers={"Authorization": auth})
    assert answer.status_code == 200 and answer.text == "good 198.51.100.20"
    assert anon.get("/api/ddns/nic/update", params={"hostname": f"home.{D}", "myip": "198.51.100.20"}, headers={"Authorization": auth}).text == "nochg 198.51.100.20"
    assert anon.get("/api/ddns/nic/update", params={"hostname": f"www.{D}", "myip": "198.51.100.20"}, headers={"Authorization": auth}).text == "nohost"
    bad_auth = "Basic " + base64.b64encode(b"router:wrong").decode()
    assert anon.get("/api/ddns/nic/update", params={"hostname": f"home.{D}"}, headers={"Authorization": bad_auth}).status_code == 401
    assert eventually(lambda: bind_answer(f"home.{D}.") == ["198.51.100.20"], timeout=20)
    used = client.get(f"/api/zones/{zid}/ddns-keys").json()["rows"][0]
    assert used["last_used_at"]
    actors = {r["actor"] for r in client.get("/api/audit", params={"action": "zone.dynamic"}).json()["rows"]}
    assert f"ddns:router.{D}" in actors
    versions = client.get(f"/api/zones/{zid}/versions").json()["rows"]
    assert any(f"ddns:router.{D}" in v["actors"] for v in versions)

    # Off: updates are not routed to dnsone-ddns any more.
    assert client.patch(f"/api/zones/{zid}/ddns-keys/{key['id']}", json={"enabled": False}).status_code == 200
    up = dns.update.UpdateMessage(f"{D}.", keyring=keyring)
    up.replace("home", 60, "A", "198.51.100.30")
    with pytest.raises(dns.tsig.PeerBadKey):            # a disabled key is unknown
        _send(up)
    from dnsone import health
    from dnsone.db import session_scope
    with session_scope() as db:
        checks = {c["name"]: c for c in health.checks(db, cheap=True)}
    assert checks["Dynamic DNS"]["status"] == "ok", checks["Dynamic DNS"]
    client.put("/api/settings/dns-server", json={**body, "ddns": "off"})


# --------------------------------------------------------------------------- single sign-on


class FakeProvider:
    """An OpenID Connect provider: discovery, JWKS, token (with PKCE) and userinfo endpoints."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.codes: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}
        provider = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _json(self, status, body):
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802
                if self.path == "/.well-known/openid-configuration":
                    return self._json(200, provider.discovery())
                if self.path == "/jwks":
                    return self._json(200, provider.jwks())
                if self.path == "/userinfo":
                    token = self.headers.get("Authorization", "")[7:]
                    claims = provider.tokens.get(token)
                    return self._json(200 if claims else 401, claims or {"error": "invalid_token"})
                self._json(404, {})

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", 0))
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
                auth = self.headers.get("Authorization", "")
                if auth != "Basic " + base64.b64encode(b"dnsone:s3cret").decode():
                    return self._json(401, {"error": "invalid_client"})
                grant = provider.codes.pop(form.get("code", ""), None)
                if grant is None:
                    return self._json(400, {"error": "invalid_grant"})
                challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
                if challenge != grant["challenge"] or form.get("redirect_uri") != grant["redirect_uri"]:
                    return self._json(400, {"error": "invalid_grant", "error_description": "PKCE or redirect mismatch"})
                access = base64.urlsafe_b64encode(os.urandom(18)).decode()
                provider.tokens[access] = {"sub": grant["claims"]["sub"], **grant.get("userinfo", {})}
                return self._json(200, {"access_token": access, "token_type": "Bearer", "id_token": provider.id_token(grant)})

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.issuer = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def discovery(self):
        return {"issuer": self.issuer, "authorization_endpoint": f"{self.issuer}/authorize", "token_endpoint": f"{self.issuer}/token",
                "jwks_uri": f"{self.issuer}/jwks", "userinfo_endpoint": f"{self.issuer}/userinfo", "end_session_endpoint": f"{self.issuer}/logout",
                "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"], "id_token_signing_alg_values_supported": ["RS256"]}

    def jwks(self):
        numbers = self.key.public_key().public_numbers()
        enc = lambda n: base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
        return {"keys": [{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256", "n": enc(numbers.n), "e": enc(numbers.e)}]}

    def id_token(self, grant, tamper: bool = False):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        now = int(time.time())
        claims = {"iss": self.issuer, "aud": "dnsone", "iat": now, "exp": now + 300, "nonce": grant["nonce"], **grant["claims"]}
        signing = f"{b64({'alg': 'RS256', 'kid': 'k1', 'typ': 'JWT'})}.{b64(claims)}"
        signature = self.key.sign(signing.encode(), padding.PKCS1v15(), hashes.SHA256())
        if grant.get("tamper"):
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return f"{signing}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"

    def sign_in(self, client, claims: dict, userinfo: dict | None = None, tamper: bool = False, nonce: str | None = None):
        """Runs a browser through the sign-in; returns the callback's response."""
        start = client.get("/api/auth/oidc/login", follow_redirects=False)
        assert start.status_code == 303, start.text
        query = {k: v[0] for k, v in parse_qs(urlparse(start.headers["location"]).query).items()}
        assert start.headers["location"].startswith(f"{self.issuer}/authorize?") and query["code_challenge_method"] == "S256"
        code = base64.urlsafe_b64encode(os.urandom(12)).decode()
        self.codes[code] = {"claims": claims, "userinfo": userinfo or {}, "nonce": nonce or query["nonce"], "challenge": query["code_challenge"],
                            "redirect_uri": query["redirect_uri"], "tamper": tamper}
        return client.get("/api/auth/oidc/callback", params={"state": query["state"], "code": code}, follow_redirects=False)


@needs("oidc")
def test_single_sign_on(client, isp):
    from fastapi.testclient import TestClient
    provider = FakeProvider()
    config = {"enabled": True, "issuer": provider.issuer, "client_id": "dnsone", "client_secret": "s3cret", "public_url": "http://127.0.0.1",
              "label": "Sign in with Corp", "role_claim": "groups", "role_map": [{"value": "dns-admins", "role": "admin"}, {"value": "dns-viewers", "role": "viewer"}],
              "default_role": "", "auto_create": True}
    assert client.put("/api/settings/sso", json={**config, "public_url": "ftp://x"}).status_code == 422
    assert client.put("/api/settings/sso", json={**config, "role_map": [{"value": "x", "role": "nope"}]}).status_code == 422
    saved = client.put("/api/settings/sso", json=config)
    assert saved.status_code == 200 and saved.json()["config"]["client_secret_set"] and "client_secret" not in saved.json()["config"]
    assert saved.json()["config"]["redirect_uri"] == "http://127.0.0.1/api/auth/oidc/callback"
    test = client.post("/api/settings/sso/test").json()
    assert test["keys"] == 1 and not test["problems"]
    # Saving without a secret keeps the stored one.
    assert client.put("/api/settings/sso", json={**config, "client_secret": ""}).json()["config"]["client_secret_set"]

    browser = TestClient(client.app)
    assert browser.get("/api/auth/oidc").json() == {"enabled": True, "label": "Sign in with Corp"}
    done = provider.sign_in(browser, {"sub": "alice-1", "preferred_username": "alice", "name": "Alice A", "email": "alice@corp.example",
                                      "email_verified": True}, userinfo={"groups": ["staff", "dns-admins"]})
    assert done.status_code == 303 and done.headers["location"] == "/", done.headers.get("location")
    me = browser.get("/api/auth/me").json()
    assert me["user"]["username"] == "alice" and me["user"]["role"] == "admin" and me["user"]["auth_source"] == "oidc"
    logout = browser.post("/api/auth/logout", headers={"X-CSRF-Token": me["csrf"]}).json()
    assert logout["redirect"].startswith(f"{provider.issuer}/logout?id_token_hint=")

    # A local account is never taken over: same username, a new account.
    other = TestClient(client.app)
    provider.sign_in(other, {"sub": "admin-x", "preferred_username": "admin", "email": "x@corp.example"}, userinfo={"groups": ["dns-viewers"]})
    assert other.get("/api/auth/me").json()["user"]["username"] == "admin.sso"

    # No mapped role and no default role: refused.
    refused = provider.sign_in(TestClient(client.app), {"sub": "eve", "preferred_username": "eve"}, userinfo={"groups": ["staff"]})
    assert "sso_error=" in refused.headers["location"] and "no DNSOne role" in refused.headers["location"].replace("%20", " ")
    # Tampered signature, and a nonce from another sign-in.
    bad = provider.sign_in(TestClient(client.app), {"sub": "alice-1"}, tamper=True)
    assert "signature" in bad.headers["location"]
    bad = provider.sign_in(TestClient(client.app), {"sub": "alice-1"}, nonce="other")
    assert "does%20not%20belong" in bad.headers["location"] or "does not belong" in bad.headers["location"]

    # Invited: an administrator creates the account for single sign-on; the first sign-in links it.
    config["auto_create"] = False
    client.put("/api/settings/sso", json=config)
    invite = client.post("/api/users", json={"username": "bob", "email": "Bob@Corp.example", "role_id": role_id(client, "operator"), "auth_source": "oidc"})
    assert invite.status_code == 201, invite.text
    assert client.post("/api/users", json={"username": "nomail", "role_id": role_id(client, "operator"), "auth_source": "oidc"}).status_code == 422
    bob = TestClient(client.app)
    provider.sign_in(bob, {"sub": "bob-7", "preferred_username": "robert", "email": "bob@corp.example", "email_verified": True})
    me = bob.get("/api/auth/me").json()["user"]
    assert me["username"] == "bob" and me["role"] == "operator"
    stranger = provider.sign_in(TestClient(client.app), {"sub": "zed", "email": "zed@corp.example"}, userinfo={"groups": ["dns-admins"]})
    assert "Ask%20an%20administrator%20to%20invite" in stranger.headers["location"] or "invite" in stranger.headers["location"]
    users = {u["username"]: u for u in client.get("/api/users").json()["rows"]}
    assert users["bob"]["sso_linked"] and users["alice"]["auth_source"] == "oidc"
    # SSO accounts have no DNSOne password.
    assert login_fails(client, "alice")
    client.put("/api/settings/sso", json={**config, "enabled": False})
    assert TestClient(client.app).get("/api/auth/oidc").json()["enabled"] is False


def login_fails(client, username: str) -> bool:
    from fastapi.testclient import TestClient
    return TestClient(client.app).post("/api/auth/login", json={"username": username, "password": PASSWORD}).status_code == 401


# --------------------------------------------------------------------------- backup


@needs("legal")
def test_backup_keeps_new_data(client, isp):
    data = client.get("/api/settings/backup").json()
    assert set(data["sections"]) == {"zones", "ad_blocking", "settings", "legal"}
    assert any(t["name"] == "Web hosting" for t in data["templates"])
    isp_zone = next(z for z in data["zones"] if z["name"] == D)
    assert isp_zone["ddns_keys"] and isp_zone["ddns_keys"][0]["secret"]
    assert any(g["safe_search"] for g in data["groups"])
    assert {b["reference"] for b in data["legal_blocks"]} >= {"123/2026", "R-9"} and data["legal_page"]["address4"] == "192.0.2.99"
    assert data["export"]["syslog"]["enabled"] is False

    cust = login(client, "cust1")
    before = sorted(z["name"] for z in cust.get("/api/zones").json()["rows"])
    report = client.post("/api/settings/restore", json={"backup": data, "sections": ["zones", "legal"]})
    assert report.status_code == 200, report.text
    assert report.json()["legal"] == 0          # everything is already there: nothing added twice
    assert sorted(z["name"] for z in cust.get("/api/zones").json()["rows"]) == before
    zid = client.get("/api/zones", params={"q": D}).json()["rows"][0]["id"]
    assert client.get(f"/api/zones/{zid}/ddns-keys").json()["rows"][0]["name"] == f"router.{D}."
    assert any(t["name"] == "Web hosting" for t in client.get("/api/templates").json()["rows"])
