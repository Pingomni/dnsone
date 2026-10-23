"""Records the data of the public demo (demo-dns.pingomni.com) from the real backend.

Runs against a test stack (as the end-to-end tests do: DNSONE_TEST_ENV, a database that is dropped
and created). It fills a fictional ISP through the API - zones, records, DNSSEC, reverse DNS, client
groups, rules, operators, settings - adds blocklists, a day of query log and a month of statistics
straight to the database, then records the answer of every GET the console makes, and one sample
answer for the actions that are not plain create/update/delete. The result is
frontend/src/demo/fixtures.json, which the demo build answers the console's API calls from.

    DNSONE_TEST_ENV=/path/to/test.env .venv/bin/python tools/demo_fixtures.py

All names are fictional and all addresses come from documentation ranges (RFC 5737, 6598, 1918).
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[1] / "tests"))
OUT = HERE.parents[2] / "frontend" / "src" / "demo" / "fixtures.json"
PASSWORD = "demo-password-not-used-1"
random.seed(7)


def main() -> None:
    from helpers import _load_env
    os.environ.setdefault("DNSONE_TEST_DATABASE", "dnsone_demo")
    _load_env()
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, text

    from dnsone import migrate, security
    from dnsone.config import get_settings
    from dnsone.db import get_engine, session_scope
    from dnsone.models import Role, User

    get_settings.cache_clear()
    get_engine.cache_clear()
    url = os.environ["DNSONE_DATABASE_URL"]
    server, _, rest = url.rpartition("/")
    with create_engine(server + "/").begin() as conn:
        name = rest.split("?")[0]
        conn.execute(text(f"DROP DATABASE IF EXISTS `{name}`"))
        conn.execute(text(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"))
    migrate.run(get_engine(), log=lambda _m: None)
    # The test BIND may still serve the zones of an earlier recording (signed, with higher serials):
    # with the database empty, reconcile removes them, so this run starts clean.
    from dnsone.zonegen import Publisher
    Publisher().reconcile()
    with session_scope() as db:
        admin = db.query(Role).filter_by(name="admin").one()
        db.add(User(username="demo", name="Demo Administrator", email="demo@demo-isp.net", role_id=admin.id,
                    password_hash=security.hash_password(PASSWORD)))

    from dnsone.api import create_app
    c = TestClient(create_app())
    r = c.post("/api/auth/login", json={"username": "demo", "password": PASSWORD})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf"]
    samples: dict[str, object] = {}

    def ok(response, code=(200, 201)):
        assert response.status_code in code, (response.request.url, response.text[:400])
        return response.json()

    # ------------------------------------------------------------------ DNS server, operators, groups
    ok(c.put("/api/settings/dns-server", json={
        "client_networks": ["10.20.0.0/16", "100.64.0.0/10", "192.0.2.0/24", "2001:db8:1000::/40"],
        "nat_addresses": ["198.51.100.10", "198.51.100.11"], "client_qps": 200, "client_burst": 400,
        "nat_qps": 5000, "nat_burst": 10000, "public_authoritative": True}))
    ok(c.put("/api/settings/privacy", json={"level": 0, "retention_hours": 24}))
    roles = {r["name"]: r["id"] for r in ok(c.get("/api/roles"))["roles"]}
    for username, name, role in (("noc", "NOC Operator", "operator"), ("support", "Support Desk", "viewer")):
        ok(c.post("/api/users", json={"username": username, "name": name, "email": f"{username}@demo-isp.net",
                                      "role_id": roles[role], "password": PASSWORD}))

    family = ok(c.post("/api/groups", json={"name": "Family filter", "description": "Homes with the family filter add-on"}))
    business = ok(c.post("/api/groups", json={"name": "Business", "description": "Business customers: no ad-blocking", "blocking": False}))
    for gid, nets in ((family["id"], ["10.20.8.0/24", "10.20.9.0/24"]), (business["id"], ["100.64.10.0/24", "203.0.113.0/26"])):
        for net in nets:
            ok(c.post(f"/api/groups/{gid}/networks", json={"network": net, "comment": "demo"}))

    # ------------------------------------------------------------------ zones
    ns = [{"host": "ns1", "address": "192.0.2.53"}, {"host": "ns2", "address": "192.0.2.54"}]
    isp = ok(c.post("/api/zones", json={"name": "demo-isp.net", "description": "The ISP's own domain", "soa_rname": "hostmaster@demo-isp.net", "nameservers": ns}))
    other_ns = [{"host": "ns1.demo-isp.net"}, {"host": "ns2.demo-isp.net"}]
    shop = ok(c.post("/api/zones", json={"name": "shop-demo.al", "description": "Customer: online shop", "soa_rname": "hostmaster@demo-isp.net", "nameservers": other_ns}))
    voip = ok(c.post("/api/zones", json={"name": "voip-demo.net", "description": "VoIP service", "soa_rname": "hostmaster@demo-isp.net", "nameservers": other_ns}))
    old = ok(c.post("/api/zones", json={"name": "old-demo.org", "description": "Former customer (kept, not served)", "soa_rname": "hostmaster@demo-isp.net", "nameservers": other_ns}))
    rev = ok(c.post("/api/zones", json={"name": "2.0.192.in-addr.arpa", "description": "Customer pool 192.0.2.0/24", "soa_rname": "hostmaster@demo-isp.net", "nameservers": other_ns}))
    records = {
        isp["id"]: [("@", "A", "192.0.2.10", None), ("www", "A", "192.0.2.10", None), ("www", "AAAA", "2001:db8:1000::10", None),
                    ("@", "MX", "mail", 10), ("mail", "A", "192.0.2.25", None), ("@", "TXT", "v=spf1 mx -all", None),
                    ("_dmarc", "TXT", "v=DMARC1; p=quarantine; rua=mailto:dmarc@demo-isp.net", None), ("@", "CAA", '0 issue "letsencrypt.org"', None),
                    ("portal", "CNAME", "www", None), ("dns", "A", "192.0.2.53", None), ("@", "HTTPS", "1 . alpn=h2,h3", None),
                    ("_443._tcp.www", "TLSA", "3 1 1 0c72ac70b745ac19998811b131d662c9ac69dbdbe7cb23e5b514b56664c5d3d6", None)],
        shop["id"]: [("@", "A", "203.0.113.80", None), ("www", "CNAME", "shop-demo.al.", None), ("@", "MX", "mx.demo-isp.net.", 10),
                     ("@", "TXT", "v=spf1 include:demo-isp.net -all", None), ("cdn", "CNAME", "cdn.example.net.", None)],
        voip["id"]: [("sip", "A", "198.51.100.40", None), ("_sip._udp", "SRV", "5 5060 sip", 10), ("_sip._tcp", "SRV", "5 5060 sip", 10),
                     ("@", "NAPTR", '10 0 "s" "SIP+D2U" "" _sip._udp.voip-demo.net.', None)],
        old["id"]: [("@", "A", "203.0.113.99", None)],
    }
    for zid, rows in records.items():
        for name_, rtype, value, prio in rows:
            ok(c.post(f"/api/zones/{zid}/records", json={"name": name_, "type": rtype, "value": value, "priority": prio}))
    ok(c.patch(f"/api/zones/{old['id']}", json={"status": "disabled"}))
    ok(c.patch(f"/api/zones/{isp['id']}", json={"dnssec": True}))
    samples["reverse"] = ok(c.post(f"/api/zones/{rev['id']}/reverse", json={"network": "192.0.2.64/27", "template": "pool-{a}-{b}-{c}-{d}.demo-isp.net", "forward": True}))
    samples["publish"] = ok(c.post(f"/api/zones/{isp['id']}/publish"))
    samples["import_into"] = ok(c.post(f"/api/zones/{shop['id']}/import", json={"text": "blog A 203.0.113.81\nstatus CNAME www\n", "mode": "merge", "dry_run": True}))
    samples["import_new"] = ok(c.post("/api/zones/import", json={"name": "imported-demo.net", "text": "$TTL 3600\n@ SOA ns1.demo-isp.net. hostmaster.demo-isp.net. 1 7200 1800 1209600 300\n@ NS ns1.demo-isp.net.\n@ A 203.0.113.70\nwww CNAME @\n", "dry_run": True}, ), (201,))

    # ------------------------------------------------------------------ ad-blocking
    with session_scope() as db:
        from dnsone.models import Blocklist, ClientGroup
        from dnsone.system import utcnow
        default = db.query(ClientGroup).filter_by(built_in=True).one()
        fam = db.get(ClientGroup, family["id"])
        lists = [("StevenBlack unified hosts", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "hosts", "block", 162384, [default, fam]),
                 ("OISD small", "https://small.oisd.nl/domainswild", "domains", "block", 55912, [default, fam]),
                 ("Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt", "domains", "block", 31207, [default, fam]),
                 ("Adult content (family filter)", "https://blocklistproject.github.io/Lists/porn.txt", "hosts", "block", 498612, [fam]),
                 ("Common false positives", "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt", "domains", "allow", 286, [default, fam])]
        for i, (name_, url_, fmt, kind, count, groups) in enumerate(lists):
            bl = Blocklist(name=name_, url=url_, format=fmt, kind=kind, enabled=True, last_status="ok", domain_count=count,
                           last_updated=utcnow() - timedelta(hours=3 + i), last_checked=utcnow() - timedelta(minutes=40))
            bl.groups = groups
            db.add(bl)
    for pattern, action, match, gid, comment in (
            ("doubleclick.net", "block", "exact", None, "Ad network"), ("*.tracking-demo.example", "block", "exact", None, "Tracker"),
            ("ads?[0-9]*\\.", "block", "regex", None, "ad1., ads2. ..."), ("login.bank-demo.example", "allow", "exact", None, "Customer complaint #4411"),
            ("*.casino-demo.example", "nxdomain", "exact", family["id"], "Gambling (family filter)"),
            ("blocked.demo-isp.net", "redirect", "exact", None, "Walled garden test")):
        body = {"pattern": pattern, "action": action, "match_type": match, "group_id": gid, "comment": comment}
        if action == "redirect":
            body["target"] = "portal.demo-isp.net"
        ok(c.post("/api/rpz/rules", json=body))
    samples["build"] = ok(c.post("/api/rpz/build"))
    samples["pause"] = ok(c.post("/api/rpz/pause", json={"minutes": 10, "group_id": family["id"]}))
    samples["resume"] = ok(c.delete(f"/api/rpz/pause?group_id={family['id']}"))
    ok(c.put("/api/settings/alerts", json={"enabled": True, "for_minutes": 2, "repeat_hours": 6, "webhook": {"enabled": True, "url": "https://hooks.example.net/dnsone"}}))
    ok(c.post("/api/auth/tokens", json={"name": "prometheus", "read_only": True}))

    # ------------------------------------------------------------------ traffic: query log, hourly top lists, counters
    s = get_settings()
    domains = {"ok": ["www.google.com", "connectivity-check.ubuntu.com", "graph.facebook.com", "i.instagram.com", "www.youtube.com",
                      "api.whatsapp.net", "time.windows.com", "netflix.com", "www.tiktok.com", "outlook.office365.com", "apple.com",
                      "demo-isp.net", "portal.demo-isp.net", "shop-demo.al", "cdn.jsdelivr.net", "play.googleapis.com", "wikipedia.org"],
               "blocked": ["doubleclick.net", "ads1.example-adserver.net", "pixel.tracking-demo.example", "googleads.g.doubleclick.net",
                           "app-measurement.com", "casino-demo.example"],
               "allowed": ["login.bank-demo.example"]}
    clients = [f"10.20.{random.randint(0, 15)}.{random.randint(2, 250)}" for _ in range(70)] + [f"100.64.10.{i}" for i in range(2, 12)]
    qtypes = [(1, 60), (28, 25), (65, 8), (5, 3), (15, 2), (16, 2)]
    from dnsone.db import get_engine as engine
    now = time.time()
    rows = []
    for i in range(6000):
        ts = now - 86400 + i * (86400 / 6000) + random.random()
        status = random.choices(["ok", "blocked", "allowed"], [88, 11, 1])[0]
        qname = random.choice(domains[status])
        qtype = random.choices([q for q, _ in qtypes], [w for _, w in qtypes])[0]
        rcode = 3 if status == "blocked" else random.choices([0, 3, 2], [96, 3, 1])[0]
        rows.append({"node": s.node_name, "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) + f".{int(ts % 1 * 1000):03d}",
                     "client": random.choice(clients), "qname": qname, "qtype": qtype, "rcode": rcode, "status": status,
                     "latency_us": random.randint(200, 2000) if status != "ok" or random.random() < .7 else random.randint(8000, 90000)})
    with engine().begin() as conn:
        conn.execute(text("INSERT INTO query_log (node, ts, client, qname, qtype, rcode, status, latency_us) VALUES "
                          "(:node, :ts, :client, :qname, :qtype, :rcode, :status, :latency_us)"), rows)
        hourly = []
        for h in range(24 * 30):
            hour = time.strftime("%Y-%m-%d %H:00:00", time.gmtime(now - h * 3600))
            load = 0.55 + 0.45 * abs(((h % 24) - 4) / 20)  # quiet at night, busy in the evening
            per_hour = int(900_000 * load * random.uniform(.9, 1.1))
            def add(dim, item, hits):
                hourly.append({"hour": hour, "dimension": dim, "node": s.node_name, "item": item, "hits": max(1, int(hits))})
            for status_, share in (("ok", .87), ("blocked", .12), ("allowed", .01)):
                add("status", status_, per_hour * share)
            for j, d in enumerate(domains["ok"]):
                add("domain", d, per_hour * .5 / (j + 1.5))
            for j, d in enumerate(domains["blocked"]):
                add("blocked", d, per_hour * .1 / (j + 1.2))
            for j, cl in enumerate(clients[:25]):
                add("client", cl, per_hour * .02 / (j * .3 + 1))
                add("client_blocked", cl, per_hour * .003 / (j * .3 + 1))
            for q, w in qtypes:
                add("qtype", {1: "A", 28: "AAAA", 65: "HTTPS", 5: "CNAME", 15: "MX", 16: "TXT"}[q], per_hour * w / 100)
            for rc, w in (("NOERROR", .86), ("NXDOMAIN", .13), ("SERVFAIL", .01)):
                add("rcode", rc, per_hour * w)
        conn.execute(text("INSERT INTO query_stats_hourly (hour, dimension, node, item, hits) VALUES (:hour, :dimension, :node, :item, :hits) "
                          "ON DUPLICATE KEY UPDATE hits = hits + VALUES(hits)"), hourly)
        conn.execute(text("DELETE FROM stats_samples"))
        q = b = hits = miss = sf = dr = 0
        samples_rows = []
        for m in range(24 * 60, -1, -1):
            minute = now - m * 60
            hour_of_day = time.gmtime(minute).tm_hour
            qps = 2600 * (0.55 + 0.45 * abs((hour_of_day - 4) / 20)) * random.uniform(.92, 1.08)
            q += qps * 60
            b += qps * 60 * .115
            hits += qps * 60 * .82
            miss += qps * 60 * .18
            sf += qps * 60 * .002
            dr += qps * 60 * .0004
            samples_rows.append({"node": s.node_name, "at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(minute)),
                                 "q": int(q), "b": int(b), "h": int(hits), "m": int(miss), "s": int(sf), "d": int(dr)})
        conn.execute(text("INSERT INTO stats_samples (node, sampled_at, queries, blocked, cache_hits, cache_misses, servfail, dropped) "
                          "VALUES (:node, :at, :q, :b, :h, :m, :s, :d)"), samples_rows)
        conn.execute(text("UPDATE settings SET value = JSON_SET(value, '$.entries', 748123) WHERE name = 'rpz.state'"))
    from dnsone import cluster
    with session_scope() as db:
        cluster.heartbeat(db)
    time.sleep(3)  # BIND signs demo-isp.net

    # ------------------------------------------------------------------ record
    fixtures: dict[str, object] = {}
    texts: dict[str, str] = {}

    def record(path: str) -> None:
        response = c.get(path)
        assert response.status_code == 200, (path, response.status_code, response.text[:300])
        if response.headers.get("content-type", "").startswith("application/json"):
            fixtures[path] = response.json()
        else:
            texts[path] = response.text

    for path in ("/api/auth/me", "/api/dashboard", "/api/system/health", "/api/alerts", "/api/stats/summary?hours=24",
                 "/api/zones?size=500", "/api/queries?limit=500", "/api/queries/history?days=30", "/api/groups", "/api/rpz/status",
                 "/api/rpz/rules?size=500", "/api/rpz/blocklists?size=500", "/api/audit?size=500", "/api/settings/dns-server",
                 "/api/settings/privacy", "/api/settings/alerts", "/api/settings/overview", "/api/settings/backup", "/api/cluster",
                 "/api/users?size=500", "/api/roles", "/api/auth/2fa", "/api/auth/tokens",
                 f"/api/groups/lookup?client={clients[0]}", "/api/groups/lookup?client=10.20.8.20",
                 "/api/rpz/lookup?domain=doubleclick.net", "/api/rpz/lookup?domain=wikipedia.org",
                 "/api/cluster/secondary-config?primary=192.0.2.53"):
        record(path)
    for hours in (1, 24, 168, 720):
        record(f"/api/queries/summary?hours={hours}")
        for dimension in ("domain", "blocked", "client"):
            record(f"/api/queries/top?dimension={dimension}&hours={hours}&limit=15")
    for zone in fixtures["/api/zones?size=500"]["rows"]:
        zid = zone["id"]
        for path in (f"/api/zones/{zid}", f"/api/zones/{zid}/records?size=500", f"/api/zones/{zid}/preview", f"/api/zones/{zid}/dnssec", f"/api/zones/{zid}/export"):
            record(path)
    for g in fixtures["/api/groups"]["rows"]:
        record(f"/api/groups/{g['id']}")
    for u in fixtures["/api/users?size=500"]["rows"]:
        record(f"/api/users/{u['id']}/tokens")

    # Test-stack details out, production-like ones in.
    blob = json.dumps({"fixtures": fixtures, "texts": texts, "samples": samples}, separators=(",", ":"))
    stack = str(Path(os.environ["DNSONE_ZONES_DIR"]).parent)
    for old_, new_ in ((f"{stack}/zones", "/var/lib/bind/zones"), (f"{stack}/etc/bind/dnsone/zones.conf", "/etc/bind/dnsone/zones.conf"),
                       (f"{stack}/lib/rpz", "/var/lib/dnsone/rpz"), (f"{stack}/log", "/var/log/dnsone"), (f"{stack}/lib", "/var/lib/dnsone"),
                       (f'"{s.node_name}"', '"dns1"'), ("testclient", "10.20.0.15"), ("dnsone_demo", "dnsone")):
        blob = blob.replace(old_, new_)
    data = json.loads(blob)
    data["fixtures"]["/api/system/health"] = {"status": "ok", "checks": [
        {"name": "MySQL", "status": "ok", "detail": "connected"},
        {"name": "BIND (rndc)", "status": "ok", "detail": "number of zones: 105 (99 automatic)"},
        {"name": "BIND (DNS)", "status": "ok", "detail": "NOERROR in 1 ms"},
        {"name": "PowerDNS Recursor", "status": "ok", "detail": "recursor 4.9.3"},
        {"name": "dnsdist", "status": "ok", "detail": "dnsdist 1.8.3"},
        {"name": "Encrypted DNS", "status": "ok", "detail": "DoT 203.0.113.53:853, DoH 203.0.113.53:443; certificate dns.demo-isp.net valid for 71 more days"},
        {"name": "Zone publishing", "status": "ok", "detail": "all zones published"},
        {"name": "RPZ", "status": "ok", "detail": "serial 2026102405, 748,123 triggers"},
        {"name": "Query log", "status": "ok", "detail": "full: 41,822,310 answers since start, 0 dropped"},
        {"name": "Client policies", "status": "ok", "detail": "the Recursor runs the current groups, pauses and regex rules"},
        {"name": "DNS server settings", "status": "ok", "detail": "dnsdist runs the current networks, rate limits and regex rules"},
        {"name": "Disk (zones)", "status": "ok", "detail": "71% free"},
        {"name": "Disk (data)", "status": "ok", "detail": "71% free"}]}
    data["fixtures"]["/api/alerts"] = {"active": []}
    # The test stack runs no query-log collector and only a few RPZ rules: show a busy, healthy server.
    for key, value in data["fixtures"].items():
        if key.startswith("/api/queries/summary"):
            value["collectors"] = [{"node": "dns1", "last_message_at": value.get("oldest_row"), "receiving": True}]
    entries = 748123
    data["fixtures"]["/api/rpz/status"]["state"]["entries"] = entries
    data["fixtures"]["/api/dashboard"]["rpz"]["entries"] = entries
    data["fixtures"]["/api/settings/overview"]["rpzEntries"] = entries
    for metric in data["fixtures"]["/api/dashboard"]["metrics"]:
        if metric["label"].startswith("Blocked domains"):
            metric["value"] = f"{entries:,}"
    data["recorded_at"] = int(now)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, separators=(",", ":")))
    print(f"{OUT}: {OUT.stat().st_size // 1024} KB, {len(data['fixtures'])} answers, {len(data['texts'])} files, {len(data['samples'])} samples")


if __name__ == "__main__":
    main()
