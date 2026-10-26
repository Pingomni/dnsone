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

    def issue(expires: date, features=("all",), customer="Test ISP") -> str:
        payload = json.dumps({"v": 1, "id": "t1", "customer": customer, "issued": "2026-01-01", "expires": expires.isoformat(),
                              "features": list(features)}).encode()
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
