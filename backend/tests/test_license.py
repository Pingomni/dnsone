"""DNSOne Pro licences (license.py, edition.py): signing, states and what each lets a Pro feature do. No services needed."""
from __future__ import annotations

import base64
import json
from datetime import date, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dnsone import edition, license


@pytest.fixture()
def signer(monkeypatch):
    """A signing key the licence module trusts for this test only."""
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    monkeypatch.setattr(license, "PUBLIC_KEYS", [public])

    def issue(expires: date, features=("all",), customer="Test ISP", **extra) -> str:
        payload = json.dumps({"v": 1, "id": "t1", "customer": customer, "issued": "2026-01-01", "expires": expires.isoformat(),
                              "features": list(features), **extra}).encode()
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
        return f"DNSONE1.{b64(payload)}.{b64(key.sign(payload))}"

    return issue


def use(monkeypatch, state: dict) -> None:
    monkeypatch.setattr(license, "current", lambda: state)


def test_valid_key(signer):
    lic = license.describe(license.parse(signer(date.today() + timedelta(days=30))))
    assert lic["state"] == "valid" and lic["customer"] == "Test ISP" and lic["features"] == list(license.FEATURES) and lic["days_left"] == 30


def test_expiry_and_feature_list(signer):
    assert license.describe(license.parse(signer(date.today() - timedelta(days=1))))["state"] == "expired"
    assert license.describe(license.parse(signer(date.today())))["state"] == "valid"  # the expiry day still counts
    assert license.parse(signer(date.today(), features=("protection", "nonsense")))["features"] == ["protection"]


def test_rejected_keys(signer):
    good = signer(date.today())
    head, payload, sig = good.split(".")
    forged = json.loads(base64.urlsafe_b64decode(payload + "=="))
    forged["expires"] = "2099-12-31"
    forged_b64 = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    for bad in ("", "hello", "DNSONE1.x", f"{head}.{forged_b64}.{sig}", good[:-4] + "AAAA"):
        with pytest.raises(license.LicenseError):
            license.parse(bad)
    assert license.parse("  " + good[:40] + "\n" + good[40:] + "\n")  # pasted with line breaks: fine


def test_states_and_pro_features(monkeypatch):
    feature = edition.pro("legal")
    use(monkeypatch, license.describe(None))
    assert not feature and not feature.writable and edition.name() == "community" and edition.features() == []
    use(monkeypatch, {"state": "valid", "features": ["legal"]})
    assert feature and feature.writable and edition.features() == ["legal"] and not edition.pro("protection")
    # Expired: keeps running (DNS answers do not change) but can no longer be changed.
    use(monkeypatch, {"state": "expired", "features": ["legal"]})
    assert feature and not feature.writable and edition.name() == "pro"
    assert edition.pro("api.legal").feature == "legal" and feature.POLICY  # attributes pass through to the module


def test_querylog_without_licence(monkeypatch):
    """The query log collector runs without the logexport licence: export off, its state still reported."""
    import asyncio

    from dnsone import querylog
    use(monkeypatch, license.describe(None))
    collector = querylog.Collector()
    monkeypatch.setattr(collector, "_read_privacy", lambda: None)
    asyncio.run(collector._reload_privacy())
    assert collector.syslog.state() is not None and not collector.syslog.wants("NOERROR")


class FakeDb:
    """The settings rows license.get/store/remove read and write (a cluster's shared table)."""

    def __init__(self, nodes: dict[str, str] | None = None):
        from dnsone.models import Setting
        self.rows = {f"node.{name}": Setting(name=f"node.{name}", value={"node": name, "server_id": sid, "last_seen": "2999-01-01T00:00:00"})
                     for name, sid in (nodes or {}).items()}

    def get(self, _model, name):
        return self.rows.get(name)

    def add(self, row):
        self.rows[row.name] = row

    def delete(self, row):
        self.rows.pop(row.name, None)

    def scalars(self, _stmt):
        return [r for n, r in self.rows.items() if n.startswith("node.")]


def test_server_id(monkeypatch, tmp_path):
    from dnsone.config import get_settings
    (tmp_path / "machine-id").write_text("0123456789abcdef0123456789abcdef\n")
    monkeypatch.setenv("DNSONE_DATABASE_URL", "mysql+pymysql://x:y@127.0.0.1/z")
    monkeypatch.setenv("DNSONE_MACHINE_ID_FILE", str(tmp_path / "machine-id"))
    get_settings.cache_clear()
    license.server_id.cache_clear()
    try:
        sid = license.server_id()
        assert license.SERVER_ID.match(sid) and "0123" not in sid  # a hash, not the machine ID
        license.server_id.cache_clear()
        assert license.server_id() == sid  # stable
        (tmp_path / "machine-id").write_text("fedcba9876543210fedcba9876543210\n")
        license.server_id.cache_clear()
        assert license.server_id() != sid  # another machine, another ID
    finally:
        get_settings.cache_clear()
        license.server_id.cache_clear()


def test_keys_for_a_server_or_a_cluster(signer, monkeypatch):
    here, other, far = "DNS1-AAAA-BBBB-CCCC-DDDD", "DNS1-EEEE-FFFF-GGGG-HHHH", "DNS1-QQQQ-RRRR-SSSS-TTTT"
    monkeypatch.setattr(license, "server_id", lambda: here)
    monkeypatch.setattr(license, "invalidate", lambda: None)
    soon = date.today() + timedelta(days=30)

    # A key names its server and how many servers it covers; a damaged count is refused.
    assert license.parse(signer(soon, server=here))["servers"] == 1
    assert license.parse(signer(soon, server=here, servers=2))["servers"] == 2
    for bad in ({"server": "dns1-nope"}, {"server": here, "servers": 0}, {"server": here, "servers": "two"}):
        with pytest.raises(license.LicenseError):
            license.parse(signer(soon, **bad))

    # This server: installed, one of one.
    db = FakeDb({"ns1": here})
    lic = license.store(db, signer(soon, server=here))
    assert lic["server"] == here and license.get(db)["state"] == "valid"
    assert license.covered(db, license.get(db)) == {"servers_used": 1, "servers_licensed": 1, "over": False}

    # Another server's key is refused, and one already stored for it is ignored.
    with pytest.raises(license.LicenseError, match="this server is " + here):
        license.store(db, signer(soon, server=far))
    db.rows["license"].value = {"key": signer(soon, server=far)}
    assert license.get(db)["state"] == "none" and "not in this cluster" in license.get(db)["error"]

    # A cluster: one key, for any of its servers, covers them all; a third server only warns.
    cluster = FakeDb({"ns1": here, "ns2": other})
    license.store(cluster, signer(soon, server=other, servers=2))
    assert license.get(cluster)["state"] == "valid"
    assert license.covered(cluster, license.get(cluster)) == {"servers_used": 2, "servers_licensed": 2, "over": False}
    cluster.add(FakeDb({"ns3": far}).rows["node.ns3"])
    assert license.get(cluster)["state"] == "valid" and license.covered(cluster, license.get(cluster))["over"] is True

    # A server not heard from for a day no longer counts.
    cluster.rows["node.ns3"].value = {**cluster.rows["node.ns3"].value, "last_seen": "2020-01-01T00:00:00"}
    assert license.covered(cluster, license.get(cluster))["over"] is False

    # Keys from before 1.5.12 name no server: valid anywhere, for any number of servers.
    legacy = FakeDb({"ns1": here, "ns2": other, "ns3": far})
    license.store(legacy, signer(soon))
    assert license.get(legacy)["server"] is None and license.covered(legacy, license.get(legacy))["over"] is False
    license.remove(legacy)
    assert license.get(legacy)["state"] == "none"


def test_room_in_a_cluster_licence(signer):
    """Before a server joins: does the cluster's licence (read from the primary's database) have a place for it?"""
    a, b, c = "DNS1-AAAA-BBBB-CCCC-DDDD", "DNS1-EEEE-FFFF-GGGG-HHHH", "DNS1-QQQQ-RRRR-SSSS-TTTT"
    soon, now = date.today() + timedelta(days=30), "2999-01-01T00:00:00"
    nodes = [{"server_id": a, "last_seen": now}]
    assert "no DNSOne Pro licence" in license.room(None, nodes, b)
    assert "not valid" in license.room("DNSONE1.bad.key", nodes, b)
    assert "expired" in license.room(signer(date.today() - timedelta(days=1), server=a, servers=3), nodes, b)
    assert license.room(signer(soon), nodes, b) is None                       # from before 1.5.11: any number
    two = signer(soon, server=a, servers=2)
    assert license.room(two, nodes, b) is None                                # 1 of 2: a place
    full = nodes + [{"server_id": b, "last_seen": now}]
    assert license.room(two, full, b) is None                                 # already in it (joining again)
    assert "covers 2 servers and 2 are in use: ask for a licence for 3" in license.room(two, full, c)
    gone = [{"server_id": a, "last_seen": now}, {"server_id": b, "last_seen": "2020-01-01T00:00:00"}]
    assert license.room(two, gone, c) is None                                 # a server gone a day frees its place
