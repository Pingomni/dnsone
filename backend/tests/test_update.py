"""Settings → Overview → Software update: the latest release from GitHub (a fake API in this file), the
install request the console leaves for dnsone-update.path, and the progress dnsone-update reports."""

from __future__ import annotations

import http.server
import json
import threading

import pytest

from helpers import ENV, PASSWORD

pytestmark = pytest.mark.skipif(not ENV, reason="DNSONE_TEST_ENV not set")


class FakeGitHub(http.server.BaseHTTPRequestHandler):
    release: dict | None = None
    calls = 0

    def do_GET(self):  # noqa: N802
        type(self).calls += 1
        if self.path != "/repos/Pingomni/dnsone/releases/latest" or self.release is None:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(self.release).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def github(monkeypatch, tmp_path):
    from dnsone import updates
    from dnsone.config import get_settings

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeGitHub)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(updates, "API", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("DNSONE_UPDATE_REQUEST_DIR", str(tmp_path / "update"))
    monkeypatch.setenv("DNSONE_UPDATE_STATUS_DIR", str(tmp_path / "update-status"))
    get_settings.cache_clear()
    updates._cache.clear()
    FakeGitHub.release = None
    FakeGitHub.calls = 0
    yield tmp_path
    server.shutdown()
    monkeypatch.undo()
    get_settings.cache_clear()
    updates._cache.clear()


def release(tag: str) -> dict:
    return {"tag_name": tag, "body": f"What is new in {tag}", "html_url": f"https://github.com/Pingomni/dnsone/releases/tag/{tag}",
            "published_at": "2026-10-24T20:00:00Z"}


def test_software_update(client, github):
    from dnsone import __version__

    # No release yet.
    data = client.get("/api/settings/update").json()
    assert data["installed"] == __version__
    assert data["latest"] is None and not data["available"]
    assert "No DNSOne release" in data["error"]

    # A newer release; the answer is cached until "Check for updates".
    FakeGitHub.release = release("v99.0.0")
    assert client.get("/api/settings/update").json()["latest"] is None
    data = client.get("/api/settings/update?refresh=1").json()
    assert data["available"] and data["latest"]["version"] == "99.0.0" and data["latest"]["notes"] == "What is new in v99.0.0"
    calls = FakeGitHub.calls
    client.get("/api/settings/update")
    assert FakeGitHub.calls == calls

    # Not set up on this server (no request directory): the console says how to set it up.
    assert data["can_install"] is False
    response = client.post("/api/settings/update")
    assert response.status_code == 409 and "sudo dnsone-update" in response.json()["message"]

    # Set up: the request is left for dnsone-update.path, once.
    (github / "update").mkdir()
    assert client.get("/api/settings/update").json()["can_install"] is True
    response = client.post("/api/settings/update")
    assert response.status_code == 200, response.text
    request = json.loads((github / "update" / "request").read_text())
    assert request["by"] == "admin" and request["version"] == "99.0.0"
    assert client.get("/api/settings/update").json()["requested"] is True
    assert client.post("/api/settings/update").status_code == 409
    assert client.get("/api/audit", params={"action": "settings.update"}).json()["total"] == 1

    # dnsone-update --console picks it up and reports its progress.
    (github / "update" / "request").unlink()
    (github / "update-status").mkdir()
    (github / "update-status" / "status.json").write_text(json.dumps(
        {"state": "running", "from": __version__, "to": "99.0.0", "started": "2026-10-24T20:01:00+00:00", "finished": ""}))
    (github / "update-status" / "update.log").write_text("== 1. Downloading DNSOne 99.0.0\n")
    data = client.get("/api/settings/update").json()
    assert data["progress"]["state"] == "running" and "Downloading" in data["progress"]["log"]
    assert client.post("/api/settings/update").status_code == 409

    (github / "update-status" / "status.json").write_text(json.dumps(
        {"state": "failed", "from": __version__, "to": "99.0.0", "started": "2026-10-24T20:01:00+00:00", "finished": "2026-10-24T20:03:00+00:00"}))
    data = client.get("/api/settings/update").json()
    assert data["progress"]["state"] == "failed" and data["progress"]["to"] == "99.0.0"

    # Nothing newer: nothing to install.
    FakeGitHub.release = release(f"v{__version__}")
    data = client.get("/api/settings/update?refresh=1").json()
    assert not data["available"] and data["error"] is None
    response = client.post("/api/settings/update")
    assert response.status_code == 409 and "up to date" in response.json()["message"]

    # Administrators only.
    from fastapi.testclient import TestClient
    from dnsone.api import create_app
    with TestClient(create_app()) as other:
        r = other.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD})
        other.headers["X-CSRF-Token"] = r.json()["csrf"]
        assert other.get("/api/settings/update").status_code == 403
        assert other.post("/api/settings/update").status_code == 403
