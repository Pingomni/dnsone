"""End-to-end tests of DNSOne 1.5: zone transfers to customers' secondaries (and every other transfer
refused), customer quotas, the resolver settings (ECS, serve-stale), DNSSEC kept in step with a hosted
parent (CDS, checkds, key rollover), attack protection in dnsdist, and the firewall's apply, confirm and
rollback (with nft replaced: changing the test machine's firewall needs root).

Same test stack as test_features.py, plus in the env file:
    DNSONE_RECURSOR_SETTINGS_FILE   a file in the test Recursor's include-dir
    DNSONE_RECURSOR_RESTART         a command that restarts the test Recursor
    DNSONE_FIREWALL_REQUEST_DIR, DNSONE_FIREWALL_STATUS_DIR   two writable directories
The DNSSEC test shortens BIND's key timings for its own zones (about two minutes).
"""

from __future__ import annotations

import json
import os
import random
import socket
import string
import subprocess
import threading
import time
from collections import Counter

import pytest

from helpers import ENV, PASSWORD, eventually, local_address

pytestmark = pytest.mark.skipif(not ENV or not os.environ.get("DNSONE_TEST_DNSDIST"), reason="DNSONE_TEST_ENV / DNSONE_TEST_DNSDIST not set")

NS = [{"host": "ns.example.net"}]


def dnsdist() -> tuple[str, int]:
    host, _, port = os.environ["DNSONE_TEST_DNSDIST"].rpartition(":")
    return host, int(port)


def login(client, username: str, password: str = PASSWORD, address: str | None = None):
    from fastapi.testclient import TestClient
    other = TestClient(client.app, client=(address, 50000)) if address else TestClient(client.app)
    response = other.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    other.headers["X-CSRF-Token"] = response.json()["csrf"]
    return other


def zone(client, name: str, **extra) -> dict:
    created = client.post("/api/zones", json={"name": name, "soa_rname": f"hostmaster@{name}", "nameservers": NS, **extra})
    assert created.status_code == 201, created.text
    zid = created.json()["id"]
    assert eventually(lambda: client.get(f"/api/zones/{zid}").json()["publish_state"] == "published", timeout=20)
    return client.get(f"/api/zones/{zid}").json()


def role_id(client, name: str) -> int:
    return next(r["id"] for r in client.get("/api/roles").json()["roles"] if r["name"] == name)


def udp(name: str, source: str, rtype: str = "A") -> str:
    import dns.message
    import dns.rcode
    query = dns.message.make_query(name, rtype)
    host, port = dnsdist()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((source, 0))
        s.settimeout(2)
        try:
            s.sendto(query.to_wire(), (host, port))
            return dns.rcode.to_text(dns.message.from_wire(s.recv(4096)).rcode())
        except OSError:
            return "timeout"


# --------------------------------------------------------------------------- zone transfers


def axfr(name: str, source: str, key: dict | None = None):
    import dns.message
    import dns.query
    import dns.rcode
    import dns.tsig
    query = dns.message.make_query(name, "AXFR")
    if key:
        query.use_tsig(dns.tsig.Key(key["name"], key["secret"], key["algorithm"]))
    host, port = dnsdist()
    response = dns.query.tcp(query, host, port=port, source=source, timeout=5)
    return dns.rcode.to_text(response.rcode()), len(response.answer)


def test_zone_transfers(client):
    z = zone(client, "xfr-v15.test")
    outside = local_address()
    # Before 1.5 anyone could transfer every hosted zone through dnsdist; now nobody may by default.
    assert axfr("xfr-v15.test", outside)[0] == "REFUSED"
    assert axfr("xfr-v15.test", "127.0.0.1")[0] == "REFUSED"

    assert client.post(f"/api/zones/{z['id']}/transfers", json={"address": "0.0.0.0/0"}).status_code == 422
    added = client.post(f"/api/zones/{z['id']}/transfers", json={"address": outside, "notify": False, "comment": "customer ns2"})
    assert added.status_code == 201, added.text
    assert client.post(f"/api/zones/{z['id']}/transfers", json={"address": outside}).status_code == 409
    assert eventually(lambda: axfr("xfr-v15.test", outside)[0] == "NOERROR", timeout=10)
    assert axfr("xfr-v15.test", "127.0.0.1")[0] == "REFUSED"

    # With a key, BIND wants the transfer signed too.
    state = client.put(f"/api/zones/{z['id']}/transfers/key", json={"enabled": True}).json()
    key = {**state["key"]}
    assert key["name"] == "transfer.xfr-v15.test." and key["secret"]
    assert eventually(lambda: axfr("xfr-v15.test", outside)[0] == "REFUSED", timeout=10)
    assert axfr("xfr-v15.test", outside, key) == ("NOERROR", axfr("xfr-v15.test", outside, key)[1])
    assert axfr("xfr-v15.test", outside, key)[1] >= 2
    assert "secret" not in client.get(f"/api/zones/{z['id']}/transfers").json()["key"]

    client.put(f"/api/zones/{z['id']}/transfers/key", json={"enabled": False})
    tid = client.get(f"/api/zones/{z['id']}/transfers").json()["rows"][0]["id"]
    assert client.delete(f"/api/zones/{z['id']}/transfers/{tid}").status_code == 200
    assert eventually(lambda: axfr("xfr-v15.test", outside)[0] == "REFUSED", timeout=10)


# --------------------------------------------------------------------------- quotas


def test_quotas(client):
    created = client.post("/api/users", json={"username": "quota-res", "role_id": role_id(client, "reseller"), "password": PASSWORD,
                                              "max_zones": 1, "max_records": 4, "api_rate": 40})
    assert created.status_code == 201, created.text
    reseller = login(client, "quota-res")
    assert reseller.get("/api/auth/me").json()["user"]["limits"] == {"max_zones": 1, "max_records": 4, "api_rate": 40}
    first = reseller.post("/api/zones", json={"name": "quota-1.test", "soa_rname": "h@quota-1.test", "nameservers": NS})
    assert first.status_code == 201
    second = reseller.post("/api/zones", json={"name": "quota-2.test", "soa_rname": "h@quota-2.test", "nameservers": NS})
    assert second.status_code == 422 and "max_zones" in second.json()["errors"]
    zid = first.json()["id"]
    codes = [reseller.post(f"/api/zones/{zid}/records", json={"name": f"h{i}", "type": "A", "value": "192.0.2.1"}).status_code for i in range(4)]
    assert codes == [201, 201, 201, 422]  # the NS record counts too
    # An administrator is not held back by the customer's quota.
    assert client.post(f"/api/zones/{zid}/records", json={"name": "admin", "type": "A", "value": "192.0.2.2"}).status_code == 201

    # A reseller's customers stay within its own limits; empty fields inherit them.
    over = reseller.post("/api/users", json={"username": "quota-cust", "role_id": role_id(client, "customer"), "password": PASSWORD, "max_records": 50})
    assert over.status_code == 422 and "max_records" in over.json()["errors"]
    cust = reseller.post("/api/users", json={"username": "quota-cust", "role_id": role_id(client, "customer"), "password": PASSWORD})
    assert cust.status_code == 201 and cust.json()["max_records"] == 4

    # API rate: requests over the minute's budget get 429 with Retry-After.
    # 100 calls: even split across two minutes, one of them goes over 40.
    responses = [reseller.get("/api/zones") for _ in range(100)]
    limited = [r for r in responses if r.status_code == 429]
    assert limited and int(limited[0].headers["Retry-After"]) >= 1


# --------------------------------------------------------------------------- resolver settings


def rec_parameter(name: str) -> str:
    from dnsone.config import get_settings
    out = subprocess.run([*get_settings().rec_control, "get-parameter", name], capture_output=True, text=True, timeout=10).stdout
    return out.strip()


def test_resolver_settings(client):
    if not os.environ.get("DNSONE_RECURSOR_SETTINGS_FILE"):
        pytest.skip("DNSONE_RECURSOR_SETTINGS_FILE not set")
    bad = client.put("/api/settings/resolver", json={"serve_stale_hours": 6, "ecs": {"enabled": True, "domains": []}})
    assert bad.status_code == 422 and "ecs.domains" in bad.json()["errors"]
    saved = client.put("/api/settings/resolver", json={"serve_stale_hours": 6, "ecs": {"enabled": True, "domains": ["cdn.example", "akamaiedge.net"]}})
    assert saved.status_code == 200, saved.text
    assert eventually(lambda: '"720"' in rec_parameter("serve-stale-extensions"), timeout=20)
    assert "cdn.example" in rec_parameter("edns-subnet-allow-list")
    assert "!100.64.0.0/10" in rec_parameter("ecs-add-for")
    assert eventually(lambda: udp("example.com", "127.0.0.1") in ("NOERROR", "SERVFAIL"), timeout=20)
    client.put("/api/settings/resolver", json={"serve_stale_hours": 12, "ecs": {"enabled": False, "domains": []}})
    assert eventually(lambda: '"1440"' in rec_parameter("serve-stale-extensions"), timeout=20)
    assert rec_parameter("edns-subnet-allow-list").endswith('=""')


# --------------------------------------------------------------------------- DNSSEC


FAST = {"DNSONE_DNSSEC_DNSKEY_TTL": "10", "DNSONE_DNSSEC_PUBLISH_SAFETY": "5", "DNSONE_DNSSEC_PROPAGATION_DELAY": "5",
        "DNSONE_DNSSEC_PARENT_DS_TTL": "10", "DNSONE_DNSSEC_PARENT_PROPAGATION_DELAY": "5", "DNSONE_DNSSEC_MAX_ZONE_TTL": "60"}


@pytest.fixture
def fast_dnssec():
    from dnsone.config import get_settings
    saved = {k: os.environ.get(k) for k in FAST}
    os.environ.update(FAST)
    get_settings.cache_clear()
    yield
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    get_settings.cache_clear()


def test_dnssec_hosted_parent_and_rollover(client, fast_dnssec):
    # A new name each run: BIND keeps a deleted zone's keys, and would bring them back with their old states.
    tag = "".join(random.choices(string.ascii_lowercase, k=6))
    parent = zone(client, f"p{tag}-v15.test", default_ttl=60)
    assert client.post(f"/api/zones/{parent['id']}/records", json={"name": "child", "type": "NS", "value": "ns.example.net."}).status_code == 201
    child = zone(client, f"child.p{tag}-v15.test", default_ttl=60)
    cid = child["id"]
    assert client.patch(f"/api/zones/{cid}", json={"soa_minimum": 60}).status_code == 200
    assert client.patch(f"/api/zones/{cid}", json={"dnssec": True}).status_code == 200
    state = lambda: client.get(f"/api/zones/{cid}/dnssec").json()  # noqa: E731
    assert state()["parent_zone"] == parent["name"]

    # BIND publishes CDS once the key reached every resolver; DNSOne copies it into the hosted parent,
    # then tells BIND the DS is there, and BIND counts the DS as published once the parent's TTL passed.
    assert eventually(lambda: state()["cds"], timeout=180, interval=5), state()
    done: list[str] = []
    def secure():
        done.extend(client.post(f"/api/zones/{cid}/dnssec/check").json()["done"])
        s = state()
        return s["secure"] and s["keys"][0]["ds"] == "omnipresent"
    assert eventually(secure, timeout=90, interval=3), (state(), done)
    assert any(f"DS records of child.p{tag}-v15.test" in d for d in done), done
    assert any("DS published" in d for d in done), done
    first = state()
    assert not first["rolling"]
    old_tag = first["keys"][0]["tag"]

    # A rollover: the new key's DS replaces the old one in the parent; the old key goes.
    rolled = client.post(f"/api/zones/{cid}/dnssec/rollover")
    assert rolled.status_code == 200, rolled.text
    assert client.post(f"/api/zones/{cid}/dnssec/rollover").status_code == 409

    def swapped():
        client.post(f"/api/zones/{cid}/dnssec/check")
        s = state()
        new = [k for k in s["keys"] if k["goal"] == "omnipresent"]
        old = [k for k in s["keys"] if k["tag"] == old_tag]
        return (len(new) == 1 and new[0]["tag"] != old_tag and new[0]["ds"] == "omnipresent" and s["secure"]
                and all(k["ds"] == "hidden" for k in old) and s["parent_ds"] == [new[0]["ds_record"]])
    assert eventually(swapped, timeout=300, interval=5), state()
    # The old key's DNSKEY stays until BIND has re-signed the zone with the new one (days with its
    # default signature timings): until then, no second rollover.
    assert state()["rolling"] and client.post(f"/api/zones/{cid}/dnssec/rollover").status_code == 409

    # Signing off with a hosted parent: DNSOne removes the DS there, and BIND unsigns.
    assert client.patch(f"/api/zones/{cid}", json={"dnssec": False}).status_code == 200
    assert eventually(lambda: (client.post(f"/api/zones/{cid}/dnssec/check"), state()["parent_ds"] == [])[1], timeout=60, interval=3), state()
    # TTLs above the signing policy's limit are refused before BIND sees them.
    assert client.patch(f"/api/zones/{parent['id']}", json={"dnssec": True}).status_code == 200
    assert client.patch(f"/api/zones/{parent['id']}", json={"default_ttl": 3600}).status_code == 200
    assert eventually(lambda: client.get(f"/api/zones/{parent['id']}").json()["publish_state"] == "error", timeout=20)
    assert "DNSONE_DNSSEC_MAX_ZONE_TTL" in client.get(f"/api/zones/{parent['id']}").json()["last_error"]
    for z in (cid, parent["id"]):
        client.delete(f"/api/zones/{z}")


# --------------------------------------------------------------------------- attack protection


def test_protection(client):
    cfg = client.get("/api/protection").json()["config"]
    tuned = json.loads(json.dumps(cfg))
    tuned["nxdomain_clients"]["enabled"] = False
    tuned["random_subdomain"].update(nxdomains=200, names=100, seconds=60)
    assert client.put("/api/protection/config", json=tuned).status_code == 200
    bad = client.put("/api/protection/config", json={**tuned, "amplification": {"enabled": True, "kbytes": 1, "seconds": 60}})
    assert bad.status_code == 422 and "amplification.kbytes" in bad.json()["errors"]
    time.sleep(3)

    # A random-subdomain flood: the domain is refused for everyone while it lasts, other names are not.
    def flood(i: int) -> str:
        name = "".join(random.choices(string.ascii_lowercase, k=12)) + ".victim-v15.invalid"
        return udp(name, f"127.0.0.{5 + i % 20}")
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(32) as pool:
        answers = Counter(pool.map(flood, range(1500)))
    assert answers["REFUSED"] > 0, answers
    assert udp("www.victim-v15.invalid", "127.0.0.30") == "REFUSED"
    assert udp("localhost", "127.0.0.30") != "REFUSED"
    now = client.get("/api/protection").json()["now"]
    assert any(n["target"] == "victim-v15.invalid." and n["kind"] == "random-subdomain" and n["action"] == "Refused" for n in now), now

    from dnsone import protection
    from dnsone.db import session_scope
    with session_scope() as db:
        assert protection.collect(db) >= 1
    events = client.get("/api/protection/events", params={"kind": "random-subdomain"}).json()["rows"]
    assert events and events[0]["target"] == "victim-v15.invalid."

    # Manual blocks: a client's queries dropped, a domain refused; never a whole TLD or your own address.
    assert client.post("/api/protection/blocks", json={"kind": "domain", "value": "com"}).status_code == 422
    assert client.post("/api/protection/blocks", json={"kind": "domain", "value": "hand-blocked-v15.example", "minutes": 5}).status_code == 201
    assert client.post("/api/protection/blocks", json={"kind": "client", "value": "127.0.0.44", "reason": "test"}).status_code == 201
    assert eventually(lambda: udp("a.hand-blocked-v15.example", "127.0.0.30") == "REFUSED", timeout=10)
    assert eventually(lambda: udp("localhost", "127.0.0.44") == "timeout", timeout=10)
    assert udp("localhost", "127.0.0.45") != "timeout"
    for b in client.get("/api/protection").json()["blocks"]:
        assert client.delete(f"/api/protection/blocks/{b['id']}").status_code == 200
    assert client.put("/api/protection/config", json=cfg).status_code == 200
    assert eventually(lambda: udp("localhost", "127.0.0.44") != "timeout", timeout=10)


# --------------------------------------------------------------------------- firewall


@pytest.fixture
def fake_nft():
    """dnsone-firewall with nft replaced: records the scripts instead of changing the machine's firewall."""
    from dnsone import firewall
    from dnsone.config import get_settings
    s = get_settings()
    if not os.environ.get("DNSONE_FIREWALL_REQUEST_DIR"):
        pytest.skip("DNSONE_FIREWALL_REQUEST_DIR not set")
    s.firewall_request_dir.mkdir(parents=True, exist_ok=True)
    s.firewall_status_dir.mkdir(parents=True, exist_ok=True)
    (s.firewall_status_dir / "status.json").unlink(missing_ok=True)
    scripts: list[str] = []

    class Helper(firewall._Helper):
        def nft(self, script, check=False):
            if "policy drop" in script and "management4" not in script:
                return False, "no management set"
            if not check:
                scripts.append(script)
            return True, ""

        def current_table(self):
            return "table inet dnsone\ndelete table inet dnsone\n# before\n"

        @staticmethod
        def ufw_active():
            return False

    def run_once():
        assert eventually(lambda: (s.firewall_request_dir / "request").exists(), timeout=10)
        return Helper(s).apply()

    saved = firewall.CONFIRM_SECONDS
    yield scripts, run_once
    firewall.CONFIRM_SECONDS = saved


def test_firewall(client, fake_nft):
    from dnsone import firewall
    from dnsone.db import session_scope
    scripts, run_once = fake_nft
    admin = login(client, "admin", address="10.99.0.5")
    assert admin.put("/api/firewall/config", json={"enabled": True, "management_networks": []}).status_code == 422
    assert admin.put("/api/firewall/config", json={"enabled": True, "management_networks": ["10.98.0.0/24"]}).status_code == 200
    refused = admin.post("/api/firewall/apply")
    assert refused.status_code == 422 and "10.99.0.5" in refused.json()["message"]
    assert admin.put("/api/firewall/config", json={"enabled": True, "management_networks": ["10.99.0.0/24", "2001:db8:99::/48"], "dot": True}).status_code == 200
    assert admin.post("/api/firewall/rules", json={"action": "drop", "protocol": "any"}).status_code == 422
    assert admin.post("/api/firewall/rules", json={"action": "drop", "protocol": "any", "source": "10.99.0.0/24"}).status_code == 422
    assert admin.post("/api/firewall/rules", json={"action": "drop", "protocol": "tcp", "ports": "0"}).status_code == 422
    assert admin.post("/api/firewall/rules", json={"action": "drop", "protocol": "any", "source": "198.51.100.0/24", "comment": "abuse"}).status_code == 201
    assert admin.post("/api/firewall/rules", json={"action": "accept", "protocol": "tcp", "source": "192.0.2.10", "ports": "3306, 9100"}).status_code == 201
    state = admin.get("/api/firewall").json()
    assert state["pending"] and state["status"]["state"] == "none"
    for line in ("ip saddr @management4 tcp dport { 22, 80, 443 } accept", 'ip saddr 198.51.100.0/24 drop comment "rule',
                 "ip saddr 192.0.2.10/32 tcp dport { 3306, 9100 } accept", "udp dport 53 accept", "tcp dport 853 accept"):
        assert line in state["preview"], state["preview"]

    # Apply, and the console's confirmation.
    helper = threading.Thread(target=run_once)
    helper.start()
    applied = admin.post("/api/firewall/apply")
    assert applied.status_code == 200, applied.text
    first = applied.json()["id"]
    assert admin.post("/api/firewall/apply").status_code == 409
    assert eventually(lambda: admin.get("/api/firewall/status").json()["state"] == "confirming", timeout=10)
    assert admin.post("/api/firewall/confirm", json={"id": first}).status_code == 200
    helper.join()
    state = admin.get("/api/firewall").json()
    assert state["status"]["state"] == "applied" and not state["pending"] and state["active"]["id"] == first
    assert "198.51.100.0/24 drop" in scripts[-1]

    # No confirmation: the previous rules come back, in nftables and as the active snapshot.
    firewall.CONFIRM_SECONDS = 2
    assert admin.post("/api/firewall/rules", json={"action": "reject", "protocol": "udp", "ports": "123"}).status_code == 201
    helper = threading.Thread(target=run_once)
    helper.start()
    assert admin.post("/api/firewall/apply").status_code == 200
    helper.join()
    state = admin.get("/api/firewall").json()
    assert state["status"]["state"] == "rolled_back" and state["active"]["id"] == first and state["pending"]
    assert scripts[-1].endswith("# before\n")

    # After the rollback this node runs the active rules: nothing for sync to do.
    with session_scope() as db:
        assert firewall.sync_request(db) is None
    # Another node (or an expired rule) runs other rules: sync asks for the active ones, without a confirmation.
    status_file = firewall.get_settings().firewall_status_dir / "status.json"
    status_file.write_text(json.dumps({**json.loads(status_file.read_text()), "state": "applied", "hash": "other"}))
    with session_scope() as db:
        assert firewall.sync_request(db) is not None
    request = json.loads((firewall.get_settings().firewall_request_dir / "request").read_text())
    assert request["confirm"] is False and request["id"] == first
    (firewall.get_settings().firewall_request_dir / "request").unlink()

    # Turning it off removes the table.
    assert admin.put("/api/firewall/config", json={"enabled": False, "management_networks": ["10.99.0.0/24"]}).status_code == 200
    helper = threading.Thread(target=run_once)
    helper.start()
    off = admin.post("/api/firewall/apply").json()["id"]
    assert eventually(lambda: admin.get("/api/firewall/status").json()["state"] == "confirming", timeout=10)
    admin.post("/api/firewall/confirm", json={"id": off})
    helper.join()
    assert admin.get("/api/firewall/status").json()["state"] == "disabled"
    assert "policy drop" not in scripts[-1]
