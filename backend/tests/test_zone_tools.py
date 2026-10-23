"""End-to-end: new record types, zone import (file and AXFR) and export, bulk reverse DNS.

Needs the test stack described in test_integration.py.
"""

from __future__ import annotations

import os

import pytest

from helpers import ENV, bind_serial, dig

pytestmark = pytest.mark.skipif(not ENV, reason="DNSONE_TEST_ENV not set")

ZONE_FILE = """$ORIGIN tools-it.test.
$TTL 3600
@       IN SOA ns1 hostmaster ( 2020010101 7200 1800 1209600 300 )
@       NS    ns1
@       NS    ns.example.net.
ns1     A     192.0.2.53
www 300 A     192.0.2.10
@       MX    10 mail
mail    A     192.0.2.25
@       TXT   "v=spf1 " "mx -all"
@       NAPTR 100 10 "u" "E2U+sip" "!^.*$!sip:info@tools-it.test!" .
@       HTTPS 1 . alpn=h2,h3
_443._tcp.www TLSA 3 1 1 0c72ac70b745ac19998811b131d662c9ac69dbdbe7cb23e5b514b56664c5d3d6
host    SSHFP 4 2 123456789abcdef67890123456789abcdef67890123456789abcdef123456789
child   NS    ns.example.net.
child   DS    12345 13 2 aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
short 5 A     192.0.2.5
@       HINFO "x86" "linux"
@       DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==
"""


def _answer(name: str, rtype: str) -> list[str]:
    response = dig(name, rtype)
    return sorted(rd.to_text() for rrset in response.answer if rrset.rdtype.name == rtype for rd in rrset)


def test_create_zone_from_file_with_new_types(client):
    preview = client.post("/api/zones/import", json={"name": "tools-it.test", "text": ZONE_FILE, "dry_run": True})
    assert preview.status_code == 201, preview.text
    p = preview.json()
    assert p["added"] == 14 and p["dnssec_dropped"] == 1 and p["zone"]["default_ttl"] == 3600
    assert any("HINFO" in s for s in p["skipped"]) and any("TTL 5 changed to 60" in w for w in p["warnings"])
    assert client.get("/api/zones", params={"q": "tools-it"}).json()["total"] == 0

    created = client.post("/api/zones/import", json={"name": "tools-it.test", "text": ZONE_FILE})
    assert created.status_code == 201, created.text
    zid = created.json()["zone"]["id"]
    zone = client.get(f"/api/zones/{zid}").json()
    assert zone["publish_state"] == "published", zone["last_error"]
    # The old server's serial is kept, so the next one is above it (and today's date wins).
    assert zone["published_serial"] > 2020010101 and bind_serial("tools-it.test") == zone["published_serial"]
    assert zone["type_counts"]["NAPTR"] == 1 and zone["type_counts"]["DS"] == 1
    assert client.post("/api/zones/import", json={"name": "tools-it.test", "text": ZONE_FILE}).status_code == 409

    if not os.environ.get("DNSONE_TEST_DNSDIST"):
        pytest.skip("DNSONE_TEST_DNSDIST not set")
    assert _answer("tools-it.test.", "NAPTR") == ['100 10 "u" "E2U+sip" "!^.*$!sip:info@tools-it.test!" .']
    assert _answer("tools-it.test.", "HTTPS") == ['1 . alpn="h2,h3"']
    assert _answer("_443._tcp.www.tools-it.test.", "TLSA")[0].startswith("3 1 1 0c72ac70")
    assert _answer("host.tools-it.test.", "SSHFP")[0].startswith("4 2 123456789abcdef")
    assert _answer("short.tools-it.test.", "A") == ["192.0.2.5"]


def test_record_types_through_the_api(client):
    zid = client.get("/api/zones", params={"q": "tools-it"}).json()["rows"][0]["id"]
    ok = client.post(f"/api/zones/{zid}/records", json={"name": "_dns", "type": "SVCB", "value": "1 svc.example.net alpn=h2"})
    assert ok.status_code == 201, ok.text
    assert ok.json()["value"] == '1 svc.example.net. alpn="h2"'
    bad = client.post(f"/api/zones/{zid}/records", json={"name": "@", "type": "DS", "value": "1 13 2 " + "ab" * 32})
    assert bad.status_code == 422 and "name" in bad.json()["errors"]
    assert client.get(f"/api/zones/{zid}/records", params={"type": "SVCB"}).json()["total"] == 1
    assert client.get(f"/api/zones/{zid}").json()["publish_state"] == "published"


def test_export_and_reimport(client):
    zid = client.get("/api/zones", params={"q": "tools-it"}).json()["rows"][0]["id"]
    exported = client.get(f"/api/zones/{zid}/export")
    assert exported.status_code == 200 and 'filename="tools-it.test.zone"' in exported.headers["content-disposition"]
    text = exported.text
    assert "NAPTR" in text and "IN\tSOA" in text

    # The exported file is the zone: merging it back changes nothing.
    again = client.post(f"/api/zones/{zid}/import", json={"text": text, "mode": "merge"}).json()
    assert "added" in again, again
    assert again["added"] == 0 and again["unchanged"] == 15 and again["skipped_count"] == 0

    extra = text + "new\tA\t192.0.2.77\nwww\tCNAME\tother.example.net.\n"
    merged = client.post(f"/api/zones/{zid}/import", json={"text": extra, "mode": "merge", "dry_run": True})
    assert merged.status_code == 422  # a CNAME beside www's A in the same file: the file is refused
    merged = client.post(f"/api/zones/{zid}/import", json={"text": text + "new\tA\t192.0.2.77\n", "mode": "merge"}).json()
    assert merged["added"] == 1 and merged["unchanged"] == 15

    # Replace: the zone ends up with the file's records only.
    small = "@ NS ns.example.net.\nwww A 192.0.2.11\n"
    dry = client.post(f"/api/zones/{zid}/import", json={"text": small, "mode": "replace", "dry_run": True}).json()
    assert dry["added"] == 1 and dry["unchanged"] == 1 and dry["removed"] == 15
    no_ns = client.post(f"/api/zones/{zid}/import", json={"text": "www A 192.0.2.11\n", "mode": "replace"})
    assert no_ns.status_code == 422 and "NS" in no_ns.json()["message"]
    done = client.post(f"/api/zones/{zid}/import", json={"text": small, "mode": "replace"}).json()
    assert done["removed"] == 15
    zone = client.get(f"/api/zones/{zid}").json()
    assert zone["record_count"] == 2 and zone["publish_state"] == "published", zone["last_error"]


def test_axfr_import(client):
    zid = client.get("/api/zones", params={"q": "tools-it"}).json()["rows"][0]["id"]
    port = int(os.environ.get("DNSONE_BIND_PORT", "5301"))
    # Transfer the zone back from the test BIND (it allows transfers to 127.0.0.1).
    report = client.post(f"/api/zones/{zid}/import", json={"axfr": {"server": "127.0.0.1", "port": port}, "mode": "replace", "dry_run": True}).json()
    assert report["added"] == 0 and report["removed"] == 0 and report["unchanged"] == 2, report
    refused = client.post(f"/api/zones/{zid}/import", json={"axfr": {"server": "127.0.0.1", "port": 9}, "mode": "merge"})
    assert refused.status_code == 422 and "axfr.server" in refused.json()["errors"]
    assert client.post(f"/api/zones/{zid}/import", json={"axfr": {"server": "not-an-ip"}}).json()["errors"].get("axfr.server")


def test_bulk_reverse_dns(client):
    rev = client.post("/api/zones", json={"name": "2.0.192.in-addr.arpa", "soa_rname": "hostmaster@example.net", "nameservers": [{"host": "ns.example.net"}]})
    assert rev.status_code == 201, rev.text
    rid = rev.json()["id"]
    fwd = client.post("/api/zones", json={"name": "pool-it.test", "soa_rname": "hostmaster@pool-it.test", "nameservers": [{"host": "ns.example.net"}]}).json()

    body = {"network": "192.0.2.0/28", "template": "pool-{a}-{b}-{c}-{d}.pool-it.test", "forward": True}
    dry = client.post(f"/api/zones/{rid}/reverse", json={**body, "dry_run": True}).json()
    assert dry["addresses"] == 16 and dry["added"] == 16 and dry["forward"]["added"] == 16 and dry["forward"]["zones"] == ["pool-it.test"]
    assert dry["sample"][1] == {"address": "192.0.2.1", "name": "1", "value": "pool-192-0-2-1.pool-it.test."}

    # A hand-made PTR is kept unless overwrite is on.
    assert client.post(f"/api/zones/{rid}/records", json={"name": "5", "type": "PTR", "value": "mail.example.net."}).status_code == 201
    done = client.post(f"/api/zones/{rid}/reverse", json=body).json()
    assert done["added"] == 15 and done["skipped_count"] == 1 and done["forward"]["added"] == 15
    again = client.post(f"/api/zones/{rid}/reverse", json={**body, "overwrite": True}).json()
    assert again["added"] == 1 and again["replaced"] == 1 and again["unchanged"] == 15 and again["forward"]["added"] == 1

    assert client.post(f"/api/zones/{rid}/reverse", json={**body, "network": "192.0.3.0/24"}).json()["errors"].get("network")
    assert client.post(f"/api/zones/{fwd['id']}/reverse", json=body).json()["errors"].get("network")

    assert client.get(f"/api/zones/{rid}").json()["publish_state"] == "published"
    assert client.get(f"/api/zones/{fwd['id']}").json()["publish_state"] == "published"
    if not os.environ.get("DNSONE_TEST_DNSDIST"):
        pytest.skip("DNSONE_TEST_DNSDIST not set")
    assert _answer("5.2.0.192.in-addr.arpa.", "PTR") == ["pool-192-0-2-5.pool-it.test."]
    assert _answer("pool-192-0-2-9.pool-it.test.", "A") == ["192.0.2.9"]


def test_dnssec_signing(client, monkeypatch):
    import dns.message
    import dns.query
    import dns.rdatatype

    from helpers import eventually
    from dnsone.config import get_settings
    s = get_settings()

    def ask(name, rtype):
        q = dns.message.make_query(name, rtype, want_dnssec=True)
        q.flags &= ~0x0100
        return dns.query.tcp(q, s.bind_address, port=s.bind_port, timeout=3)

    zone = client.post("/api/zones", json={"name": "sec-it.test", "soa_rname": "hostmaster@sec-it.test",
                                            "nameservers": [{"host": "ns1", "address": "192.0.2.53"}]}).json()
    zid = zone["id"]
    assert zone["dnssec"] == "off"
    assert client.post(f"/api/zones/{zid}/records", json={"name": "www", "type": "A", "value": "192.0.2.80"}).status_code == 201
    assert client.get(f"/api/zones/{zid}/dnssec").json()["summary"] == "not signed"

    on = client.patch(f"/api/zones/{zid}", json={"dnssec": True})
    assert on.status_code == 200 and on.json()["dnssec"] == "on"
    z = client.get(f"/api/zones/{zid}").json()
    assert z["publish_state"] == "published", z["last_error"]
    assert 'dnssec-policy "dnsone";' in s.bind_zones_conf.read_text()

    info = eventually(lambda: (lambda d: d if d["keys"] else None)(client.get(f"/api/zones/{zid}/dnssec").json()), timeout=30)
    assert info, "BIND did not publish a DNSKEY"
    assert len(info["keys"]) == 1 and info["keys"][0]["flags"] == 257 and info["keys"][0]["algorithm"] == "ECDSAP256SHA256"
    assert len(info["ds"]) == 1 and info["ds"][0].split()[1:3] == ["13", "2"]
    assert not info["secure"] and "registrar" in info["summary"]
    signed = eventually(lambda: any(r.rdtype == dns.rdatatype.RRSIG for r in ask("www.sec-it.test.", "A").answer), timeout=30)
    assert signed, "www.sec-it.test A is not signed"

    # Edits keep publishing although BIND bumps the signed serial on its own.
    for i in range(3):
        assert client.post(f"/api/zones/{zid}/records", json={"name": f"h{i}", "type": "A", "value": f"192.0.2.{90 + i}"}).status_code == 201
        z = client.get(f"/api/zones/{zid}").json()
        assert z["publish_state"] == "published", z["last_error"]
    assert eventually(lambda: any(r.rdtype == dns.rdatatype.RRSIG for r in ask("h2.sec-it.test.", "A").answer), timeout=30)

    # Never unsigned while the parent still has a DS: the zone would turn bogus.
    from dnsone import dnssec
    monkeypatch.setattr(dnssec, "parent_ds", lambda name: [info["ds"][0]])
    refused = client.patch(f"/api/zones/{zid}", json={"dnssec": False})
    assert refused.status_code == 409 and "registrar" in refused.json()["message"]
    assert client.get(f"/api/zones/{zid}/dnssec").json()["secure"] is True
    monkeypatch.undo()

    off = client.patch(f"/api/zones/{zid}", json={"dnssec": False}).json()
    assert off["dnssec"] == "insecure"
    z = client.get(f"/api/zones/{zid}").json()
    assert z["publish_state"] == "published", z["last_error"]
    assert "dnssec-policy insecure;" in s.bind_zones_conf.read_text()
    assert [a.to_text() for r in ask("www.sec-it.test.", "A").answer for a in r if r.rdtype == dns.rdatatype.A] == ["192.0.2.80"]

    assert client.delete(f"/api/zones/{zid}").status_code == 200
    assert not list(s.zones_dir.glob("sec-it.test.zone*"))
