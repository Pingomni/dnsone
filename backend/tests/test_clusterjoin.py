"""Settings → Cluster, set up from the console (clusterjoin.py): adding a server on the primary, the join key,
joining and leaving on the new server, and removing it. dnsone-cluster runs in this process with the system
files in a temporary directory and the system commands recorded instead of run (named-checkconf runs for
real on the files it would check); the join key's TLS login runs against the test MySQL."""

from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from helpers import ENV, needs

pytestmark = pytest.mark.skipif(not ENV, reason="DNSONE_TEST_ENV not set")

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
CA = "-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----\n"
PASSWORD = "ab" * 24


def checkconf(*files: Path) -> tuple[int, str]:
    """named-checkconf on a configuration that includes `files`."""
    top = files[0].with_name("check.conf")
    top.write_text("".join(f'include "{f}";\n' for f in files))
    proc = subprocess.run(["named-checkconf", str(top)], capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def test_keys_and_files(tmp_path):
    from dnsone import clusterjoin as cj

    key = cj.make_key("10.0.0.11", "dnsone", "dnsone", PASSWORD, CA, "10.0.0.12")
    assert cj.parse_key(f"  {key[:30]}\n{key[30:]}  ") == {
        "primary": "10.0.0.11", "port": 3306, "database": "dnsone", "user": "dnsone", "password": PASSWORD, "ca": CA, "address": "10.0.0.12"}
    for bad in ("hello", "DNSONE-JOIN1.", key[:-12], cj.make_key("10.0.0.11", "dns;one", "dnsone", PASSWORD, CA, "10.0.0.12"),
                cj.make_key("10.0.0.11", "dnsone", "dnsone", "short", CA, "10.0.0.12"),
                cj.make_key("2001:db8::1", "dnsone", "dnsone", PASSWORD, CA, "10.0.0.12"),
                cj.make_key("10.0.0.11", "dnsone", "dnsone", PASSWORD, "not a certificate", "10.0.0.12")):
        with pytest.raises(cj.ClusterError):
            cj.parse_key(bad)

    # BIND: the address in listen-on, the catalog in options { }; both idempotent, the block removable.
    options = (DEPLOY / "bind/named.conf.options").read_text()
    listening = cj.add_listen(options, "10.0.0.11")
    assert "listen-on port 5301 { 127.0.0.1; 10.0.0.11; };" in listening
    assert cj.add_listen(listening, "10.0.0.11") == listening
    with pytest.raises(cj.ClusterError):
        cj.add_listen("options { };", "10.0.0.11")
    lines = cj.catalog_lines("catalog.dnsone", "10.0.0.11", tmp_path / "catalog")
    replica = cj.set_block(listening, lines)
    assert cj.set_block(replica, lines) == replica and cj.remove_block(replica) == listening
    (tmp_path / "options.conf").write_text(replica)
    (tmp_path / "cluster.conf").write_text(cj.render_cluster_conf("catalog.dnsone", "10.0.0.11", tmp_path / "catalog"))
    code, out = checkconf(tmp_path / "options.conf", tmp_path / "cluster.conf")
    assert code == 0, out
    # Left: neither the catalog nor catalog-zones (one without the other is an error).
    (tmp_path / "options.conf").write_text(cj.remove_block(replica))
    (tmp_path / "cluster.conf").write_text(cj.render_cluster_conf())
    assert checkconf(tmp_path / "options.conf", tmp_path / "cluster.conf")[0] == 0

    env = "# comment\nDNSONE_DATABASE_URL=mysql+pymysql://a:b@127.0.0.1/dnsone\nDNSONE_ROLE=primary\n"
    assert cj.set_env(env, {"DNSONE_ROLE": "replica", "DNSONE_X": "1"}) == \
        "# comment\nDNSONE_DATABASE_URL=mysql+pymysql://a:b@127.0.0.1/dnsone\nDNSONE_ROLE=replica\nDNSONE_X=1\n"


def _mysql_ca(conn) -> Path | None:
    with conn.cursor() as cur:
        cur.execute("SELECT @@datadir, @@ssl_ca")
        datadir, ca = cur.fetchone()
    path = Path(datadir) / (ca or "ca.pem")
    return path if path.is_file() else None


def _admin():
    import os

    import pymysql
    from sqlalchemy.engine import make_url

    from helpers import _load_env
    if "DNSONE_DATABASE_URL" not in os.environ:
        _load_env()
    url = make_url(os.environ["DNSONE_DATABASE_URL"])
    return pymysql.connect(host=url.host, port=url.port, user=url.username, password=url.password, database=url.database, autocommit=True,
                           charset="utf8mb4")


def test_join_key_logs_in_over_tls(tmp_path):
    """A key's account must use TLS, and the server's certificate must be signed by the key's CA."""
    import pymysql

    from dnsone import clusterjoin as cj
    admin = _admin()
    ca = _mysql_ca(admin)
    if ca is None:
        pytest.skip("the test MySQL has no CA certificate")
    with admin.cursor() as cur:
        cur.execute("DROP USER IF EXISTS 'dnsonejoin'@'127.0.0.1'")
        cur.execute(f"CREATE USER 'dnsonejoin'@'127.0.0.1' IDENTIFIED BY '{PASSWORD}' REQUIRE SSL")
    try:
        key = cj.parse_key(cj.make_key("127.0.0.1", "information_schema", "dnsonejoin", PASSWORD, ca.read_text(), "127.0.0.2"))
        key["port"] = admin.port
        conn = cj.connect(key)
        with conn.cursor() as cur:
            cur.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
            assert cur.fetchone()[1]
        conn.close()
        with pytest.raises(pymysql.MySQLError):  # without TLS the account is refused
            pymysql.connect(host="127.0.0.1", port=admin.port, user="dnsonejoin", password=PASSWORD, connect_timeout=5, ssl_disabled=True)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Another CA",
                        "-keyout", str(tmp_path / "other.key"), "-out", str(tmp_path / "other.pem")], check=True, capture_output=True)
        with pytest.raises(pymysql.MySQLError):  # a server whose certificate another CA signed is refused
            cj.connect({**key, "ca": (tmp_path / "other.pem").read_text()})
    finally:
        with admin.cursor() as cur:
            cur.execute("DROP USER IF EXISTS 'dnsonejoin'@'127.0.0.1'")
        admin.close()


def _system(root: Path, database_url: str) -> object:
    """A server's system files, as the installer leaves them."""
    from dnsone import clusterjoin as cj
    root.mkdir()
    p = cj.Paths(env=root / "dnsone.env", ca=root / "mysql-ca.pem", mysql_cnf=root / "zz-dnsone-cluster.cnf", mysql_ca=root / "mysql/ca.pem",
                 named_options=root / "named.conf.options", named_local=root / "named.conf.local", cluster_conf=root / "cluster.conf",
                 zones_conf=root / "zones.conf", catalog_dir=root / "catalog")
    p.env.write_text(f"DNSONE_DATABASE_URL={database_url}\nDNSONE_NODE_NAME=x\nDNSONE_ROLE=primary\n")
    shutil.copy(DEPLOY / "bind/named.conf.options", p.named_options)
    shutil.copy(DEPLOY / "bind/named.conf.local", p.named_local)
    p.zones_conf.write_text('zone "own.example" { type primary; file "/var/lib/bind/zones/own.example.zone"; };\n')
    return p


def _files(p) -> dict:
    return {f.name: f.read_text() for f in Path(p.env).parent.iterdir() if f.is_file() and f.name != "check.conf"}


@needs("api.cluster")
def test_cluster_from_the_console(client, tmp_path, monkeypatch):
    import os

    import pymysql

    from dnsone import __version__, firewall
    from dnsone import clusterjoin as cj
    from dnsone.config import get_settings
    from dnsone.db import session_scope
    from dnsone.models import Setting

    admin = _admin()
    ca = _mysql_ca(admin)
    if ca is None:
        pytest.skip("the test MySQL has no CA certificate")
    for d in ("req", "st", "req2", "st2"):
        (tmp_path / d).mkdir()
    monkeypatch.setenv("DNSONE_CLUSTER_REQUEST_DIR", str(tmp_path / "req"))
    monkeypatch.setenv("DNSONE_CLUSTER_STATUS_DIR", str(tmp_path / "st"))
    get_settings.cache_clear()
    url = os.environ["DNSONE_DATABASE_URL"]

    commands: list[list[str]] = []
    stdin: list[str] = []
    checks = {"fail": False}
    files: dict = {}

    def fake(cmd, input_text=None):
        commands.append(cmd)
        if input_text:
            stdin.append(input_text)
        if cmd[:2] == ["ufw", "status"]:
            return 0, "Status: active\n"
        if cmd == ["named-checkconf"]:
            if checks["fail"]:
                return 1, "named.conf.options: unexpected token"
            return checkconf(files["p"].named_options, files["p"].cluster_conf) if files["p"].cluster_conf.exists() else checkconf(files["p"].named_options)
        return 0, ""
    monkeypatch.setattr(cj, "run_command", fake)
    # The primary's database is this test database; the key's TLS login is test_join_key_logs_in_over_tls.
    monkeypatch.setattr(cj, "connect", lambda key, timeout=10: _admin())

    try:
        # ------------------------------------------------------------------ the primary: add a server
        r = client.post("/api/cluster/servers", json={"address": "10.0.0.12", "name": "ns2", "listen": "10.0.0.11"})
        assert r.status_code == 200, r.text
        request = json.loads((tmp_path / "req/request").read_text())
        assert request["action"] == "add" and request["address"] == "10.0.0.12" and cj.PASSWORD.match(request["password"])
        data = client.get("/api/cluster").json()
        assert data["setup"]["servers"] == [{"address": "10.0.0.12", "name": "ns2", "state": "preparing", "node": None, "message": None,
                                            "created": data["setup"]["servers"][0]["created"], "key_ready": False}]
        assert data["setup"]["busy"] and {"address": "10.0.0.12", "port": 5301, "name": "ns2"} in data["secondaries"]
        assert client.post("/api/cluster/servers", json={"address": "10.0.0.12", "listen": "10.0.0.11"}).status_code == 422
        assert client.post("/api/cluster/servers", json={"address": "10.0.0.13", "listen": "10.0.0.11"}).json()["message"].startswith("A cluster change")
        assert client.post("/api/cluster/servers", json={"address": "2001:db8::2", "listen": "10.0.0.11"}).status_code == 422
        assert client.get("/api/cluster/servers/10.0.0.12/key").status_code == 409

        primary = _system(tmp_path / "primary", url)
        primary.mysql_ca.parent.mkdir()
        shutil.copy(ca, primary.mysql_ca)
        files["p"] = primary
        assert cj.Applier(get_settings(), primary).apply() == 0, cj.status(get_settings())
        assert not (tmp_path / "req/request").exists()
        assert f"CREATE USER IF NOT EXISTS 'dnsone'@'10.0.0.12' IDENTIFIED BY '{request['password']}' REQUIRE SSL" in stdin[0].replace("`", "")
        assert primary.mysql_cnf.read_text().endswith("bind-address = 127.0.0.1,10.0.0.11\n")
        assert "listen-on port 5301 { 127.0.0.1; 10.0.0.11; };" in primary.named_options.read_text()
        assert ["systemctl", "restart", "mysql"] in commands and ["rndc", "reconfig"] in commands
        assert ["ufw", "allow", "from", "10.0.0.12", "to", "any", "port", "3306", "proto", "tcp"] in commands
        assert cj.status(get_settings())["state"] == "done"
        data = client.get("/api/cluster").json()["setup"]
        assert data["servers"][0]["state"] == "ready" and data["servers"][0]["key_ready"] and data["primary"] == "10.0.0.11"
        assert "password" not in json.dumps(data)
        key = client.get("/api/cluster/servers/10.0.0.12/key").json()["key"]
        assert cj.parse_key(key) == {"primary": "10.0.0.11", "port": 3306, "database": cj._account(url)[0], "user": "dnsone",
                                     "password": request["password"], "ca": cj.clean_pem(ca.read_text()), "address": "10.0.0.12"}

        # Asked again (an update re-running it): nothing restarts.
        commands.clear()
        (tmp_path / "req/request").write_text(json.dumps(request))
        assert cj.Applier(get_settings(), primary).apply() == 0
        assert ["systemctl", "restart", "mysql"] not in commands and ["rndc", "reconfig"] not in commands

        # The firewall opens BIND and MySQL to the servers, and BIND to the primary on a replica.
        with session_scope() as db:
            snapshot = {**firewall.draft(db), "config": {"enabled": True, "management_networks": ["192.0.2.0/24"]}}
        rules = firewall.render(snapshot)
        assert "ip saddr 10.0.0.12 tcp dport { 5301, 3306 } accept" in rules
        assert "ip saddr 10.0.0.11 meta l4proto { tcp, udp } th dport 5301 accept" in rules

        # This database has servers added: it cannot join another cluster.
        assert "Remove them first" in client.post("/api/cluster/join", json={"key": key}).json()["message"]

        # ------------------------------------------------------------------ the new server: join
        with session_scope() as db:
            db.merge(Setting(name="node.ns1", value={"node": "ns1", "role": "primary", "version": __version__, "last_seen": "2026-10-27T12:00:00"}))
        s2 = dataclasses.replace(get_settings(), node_name="ns2", cluster_request_dir=tmp_path / "req2", cluster_status_dir=tmp_path / "st2")
        replica = _system(tmp_path / "replica", "mysql+pymysql://dnsone:own@127.0.0.1:3306/dnsone?charset=utf8mb4")
        files["p"] = replica
        before = _files(replica)

        # A named-checkconf failure puts every file back.
        checks["fail"] = True
        (tmp_path / "req2/request").write_text(json.dumps({"id": "1", "action": "join", "key": key}))
        assert cj.Applier(s2, replica).apply() == 1
        assert _files(replica) == before
        assert cj.status(s2)["state"] == "failed" and "named-checkconf" in cj.status(s2)["message"]
        checks["fail"] = False

        commands.clear()
        (tmp_path / "req2/request").write_text(json.dumps({"id": "2", "action": "join", "key": key}))
        assert cj.Applier(s2, replica).apply() == 0, cj.status(s2)
        env = replica.env.read_text()
        assert f"DNSONE_DATABASE_URL={cj.database_url(cj.parse_key(key), replica.ca)}\n" in env and "DNSONE_ROLE=replica\n" in env
        assert "@10.0.0.11:3306/" in env and "ssl_ca=" in env
        assert replica.ca.read_text() == cj.clean_pem(ca.read_text()) and "\x00" not in replica.ca.read_text()
        assert cj.standalone(replica.env).read_text() == before["dnsone.env"]
        options = replica.named_options.read_text()
        assert 'zone "catalog.dnsone" default-primaries { 10.0.0.11 port 5301; }' in options
        assert "listen-on port 5301 { 127.0.0.1; 10.0.0.12; };" in options
        assert 'primaries { 10.0.0.11 port 5301; };' in replica.cluster_conf.read_text()
        assert f'include "{replica.cluster_conf}";' in replica.named_local.read_text()
        assert "own.example" not in replica.zones_conf.read_text() and "own.example" in cj.standalone(replica.zones_conf).read_text()
        assert replica.catalog_dir.is_dir()
        for cmd in (["named-checkconf"], ["systemctl", "restart", "named"], ["ufw", "allow", "from", "10.0.0.11", "to", "any", "port", "5301"],
                    ["systemctl", "restart", "dnsone-api", "dnsone-querylog", "dnsone-ddns"], ["systemctl", "start", "dnsone-sync.service"]):
            assert cmd in commands, cmd
        server = client.get("/api/cluster").json()["setup"]["servers"][0]
        assert server["state"] == "joined" and server["node"] == "ns2" and not server["key_ready"]
        with session_scope() as db:
            assert "password" not in json.dumps(db.get(Setting, "cluster.servers").value)
        assert client.get("/api/cluster/servers/10.0.0.12/key").status_code == 409

        # ------------------------------------------------------------------ the replica: leave
        with session_scope() as db:
            db.merge(Setting(name="node.ns2", value={"node": "ns2", "role": "replica", "version": __version__, "last_seen": "2026-10-27T12:00:00"}))
        s3 = dataclasses.replace(s2, role="replica", database_url=url)
        (tmp_path / "req2/request").write_text(json.dumps({"id": "3", "action": "leave"}))
        assert cj.Applier(s3, replica).apply() == 0, cj.status(s3)
        after = _files(replica)
        assert after["dnsone.env"] == before["dnsone.env"] and after["zones.conf"] == before["zones.conf"]
        assert cj.BEGIN not in after["named.conf.options"] and "catalog.dnsone" not in after["cluster.conf"]
        assert code_ok(replica)
        assert not cj.standalone(replica.env).exists()
        with session_scope() as db:
            assert db.get(Setting, "node.ns2") is None
        assert client.get("/api/cluster").json()["setup"]["servers"][0]["state"] == "left"

        # ------------------------------------------------------------------ the primary: remove
        assert client.delete("/api/cluster/servers/10.0.0.12").status_code == 200
        assert json.loads((tmp_path / "req/request").read_text())["action"] == "remove"
        stdin.clear()
        commands.clear()
        files["p"] = primary
        assert cj.Applier(get_settings(), primary).apply() == 0
        assert stdin == ["DROP USER IF EXISTS 'dnsone'@'10.0.0.12';\n"]
        assert ["ufw", "delete", "allow", "from", "10.0.0.12", "to", "any", "port", "3306", "proto", "tcp"] in commands
        data = client.get("/api/cluster").json()
        assert data["setup"]["servers"] == [] and all(s["address"] != "10.0.0.12" for s in data["secondaries"])
        assert client.get("/api/audit", params={"action": "cluster."}).json()["total"] >= 3

        # Administrators only.
        from fastapi.testclient import TestClient

        from dnsone.api import create_app
        from helpers import PASSWORD as USER_PASSWORD
        with TestClient(create_app()) as other:
            r = other.post("/api/auth/login", json={"username": "viewer", "password": USER_PASSWORD})
            other.headers["X-CSRF-Token"] = r.json()["csrf"]
            assert other.post("/api/cluster/servers", json={"address": "10.0.0.14", "listen": "10.0.0.11"}).status_code == 403
            assert other.post("/api/cluster/join", json={"key": key}).status_code == 403
    finally:
        with session_scope() as db:
            for name in ("cluster.servers", "cluster.primary", "cluster.ca", "cluster.secondaries", "node.ns1", "node.ns2"):
                row = db.get(Setting, name)
                if row is not None:
                    db.delete(row)
        admin.close()
        monkeypatch.undo()
        get_settings.cache_clear()
        _ = pymysql


def code_ok(p) -> bool:
    return checkconf(p.named_options, p.cluster_conf)[0] == 0
