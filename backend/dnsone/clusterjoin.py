# SPDX-License-Identifier: Elastic-2.0
# DNSOne Pro (LICENSE-PRO): on with a licence key, Settings → License.
"""Setting up a cluster from the console (Settings → Cluster), with no terminal on either server.

On the primary, *Add a server* with the new server's address: the API keeps it in cluster.servers
(state "preparing"), makes it a BIND secondary and leaves a request for dnsone-cluster (root, through
dnsone-cluster.path), which
  - creates a MySQL account for that address only, which must use TLS
  - lets MySQL listen on the primary's address (/etc/mysql/mysql.conf.d/zz-dnsone-cluster.cnf) and BIND
    too (listen-on in named.conf.options), so the new server reaches both
  - opens 3306 and 5301 to that address in ufw where ufw is on (DNSOne's own firewall takes the cluster's
    addresses from MySQL, firewall.py)
  - stores MySQL's CA certificate: the server is "ready" and the console shows its join key,
    DNSONE-JOIN1.<base64url JSON: the primary, the database, the account, its password, the CA, the
    new server's address>
On the new server, *Join a cluster* with that key: the API checks it reaches the primary's database with
it and that both run the same DNSOne version, and dnsone-cluster
  - points /etc/dnsone/dnsone.env at the primary's database with DNSONE_ROLE=replica (the standalone file
    is kept as dnsone.env.standalone), the CA in /etc/dnsone/mysql-ca.pem
  - makes BIND a secondary that follows the primary's catalog zone (catalog-zones in named.conf.options,
    /etc/bind/dnsone/cluster.conf) and listen on the server's address for the primary's notifies; its own
    zones are set aside (zones.conf.standalone)
  - restarts BIND and DNSOne, syncs, and marks the server "joined"
  If anything fails on the way, every file is put back.
*Leave the cluster* on a replica puts its standalone files back; *Remove* on the primary drops the server's
MySQL account and its ufw openings.

The API never changes the system: dnsone-cluster reads validated fields only from a request (addresses, a
password of hex digits, a key it parses itself) and takes the database and account from dnsone.env.

    python -m dnsone.clusterjoin apply     what dnsone-cluster.service runs (root)
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import pymysql
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from . import __version__, firewall, validation
from .config import Settings, get_settings
from .models import Setting
from .system import utcnow
from .zonegen import secondaries, set_secondaries

log = logging.getLogger(__name__)

SERVERS_KEY = "cluster.servers"
PRIMARY_KEY = "cluster.primary"
CA_KEY = "cluster.ca"
REQUEST = "request"
KEY_PREFIX = "DNSONE-JOIN1."
MYSQL_PORT = 3306
BIND_PORT = 5301
NAME = re.compile(r"[A-Za-z0-9_]{1,32}\Z")
PASSWORD = re.compile(r"[0-9a-f]{48}\Z")
PEM = re.compile(r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?\Z")
BEGIN = "// BEGIN DNSOne cluster: written by dnsone-cluster (Settings → Cluster)"
END = "// END DNSOne cluster"
LISTEN = re.compile(r"(listen-on\s+port\s+(\d+)\s*\{)([^}]*)(\};)")
COMMAND_TIMEOUT = 300


class ClusterError(Exception):
    pass


@dataclass
class Paths:
    """The system files dnsone-cluster changes (tests point them elsewhere)."""
    env: Path = Path("/etc/dnsone/dnsone.env")
    ca: Path = Path("/etc/dnsone/mysql-ca.pem")
    mysql_cnf: Path = Path("/etc/mysql/mysql.conf.d/zz-dnsone-cluster.cnf")
    mysql_ca: Path = Path("/var/lib/mysql/ca.pem")
    named_options: Path = Path("/etc/bind/named.conf.options")
    named_local: Path = Path("/etc/bind/named.conf.local")
    cluster_conf: Path = Path("/etc/bind/dnsone/cluster.conf")
    zones_conf: Path = Path("/etc/bind/dnsone/zones.conf")
    catalog_dir: Path = Path("/var/cache/bind/catalog")


PATHS = Paths()


def standalone(path: Path) -> Path:
    return path.with_name(path.name + ".standalone")


# --------------------------------------------------------------------------- join keys


def make_key(primary: str, database: str, user: str, password: str, ca: str, address: str) -> str:
    body = {"primary": primary, "port": MYSQL_PORT, "database": database, "user": user, "password": password, "ca": ca, "address": address}
    return KEY_PREFIX + base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode().rstrip("=")


def parse_key(text: str) -> dict:
    """The fields of a join key, each checked; ClusterError if it is not one."""
    key = "".join(str(text).split())
    if not key.startswith(KEY_PREFIX):
        raise ClusterError("This is not a DNSOne join key (it starts with DNSONE-JOIN1.): copy it from the primary's Settings → Cluster.")
    body = key[len(KEY_PREFIX):]
    damaged = ClusterError("The join key is damaged: copy it again, whole.")
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        out = {"primary": _ipv4(data["primary"]), "port": int(data["port"]), "database": str(data["database"]), "user": str(data["user"]),
               "password": str(data["password"]), "ca": clean_pem(str(data["ca"])), "address": _ipv4(data["address"])}
    except (ValueError, KeyError, TypeError):
        raise damaged from None
    if not (1 <= out["port"] <= 65535 and NAME.match(out["database"]) and NAME.match(out["user"])
            and PASSWORD.match(out["password"]) and PEM.match(out["ca"])):
        raise damaged
    return out


def clean_pem(text: str) -> str:
    """A certificate as PEM text; the one MySQL makes for itself ends with a NUL byte."""
    return text.replace("\r\n", "\n").strip("\x00 \n") + "\n"


def _ipv4(raw: object) -> str:
    address = ipaddress.ip_address(str(raw).strip())
    if address.version != 4:
        raise ValueError("IPv4 only")
    return str(address)


def _account(database_url: str) -> tuple[str, str]:
    """The database and the account DNSOne uses, from DNSONE_DATABASE_URL."""
    url = make_url(database_url)
    if not (url.database and url.username and NAME.match(url.database) and NAME.match(url.username)):
        raise ClusterError("DNSONE_DATABASE_URL does not name a database and an account of letters, digits and _.")
    return url.database, url.username


def database_url(key: dict, ca: Path) -> str:
    return (f"mysql+pymysql://{key['user']}:{key['password']}@{key['primary']}:{key['port']}/{key['database']}"
            f"?charset=utf8mb4&ssl_ca={ca}&ssl_check_hostname=0")


def connect(key: dict, timeout: int = 10) -> pymysql.connections.Connection:
    """The primary's database, over TLS checked against the key's CA (the certificate MySQL made for itself
    names no host, so only the CA is checked)."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(key["ca"])
    try:
        return pymysql.connect(host=key["primary"], port=key["port"], user=key["user"], password=key["password"], database=key["database"],
                               ssl={"ca": f.name, "check_hostname": False}, connect_timeout=timeout, charset="utf8mb4")
    finally:
        os.unlink(f.name)


def primary_nodes(key: dict) -> list[dict]:
    """The nodes recorded in the primary's database; ClusterError if it cannot be reached with the key or runs
    another DNSOne version than this server."""
    try:
        conn = connect(key)
    except pymysql.MySQLError as exc:
        detail = exc.args[1] if len(exc.args) > 1 else str(exc)
        raise ClusterError(f"Cannot reach the primary's database at {key['primary']}:{key['port']} with this key ({detail}). "
                           "Is the server ready on the primary (Settings → Cluster), and is 3306 open to this server?") from None
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM settings WHERE name LIKE 'node.%'")
            nodes = [json.loads(v) if isinstance(v, (str, bytes)) else v for (v,) in cur.fetchall()]
    finally:
        conn.close()
    primaries = sorted((n for n in nodes if n.get("role") == "primary"), key=lambda n: str(n.get("last_seen")))
    if not primaries:
        raise ClusterError("The primary's database has no DNSOne primary in it.")
    version = primaries[-1].get("version")
    if version != __version__:
        raise ClusterError(f"The primary runs DNSOne {version} and this server {__version__}: "
                           "update them to the same version first (Settings → Overview → Software update).")
    return nodes


# --------------------------------------------------------------------------- the console's side (user dnsone)


def _value(db: Session, key: str) -> dict:
    row = db.get(Setting, key)
    return dict(row.value or {}) if row else {}


def _put(db: Session, key: str, value: dict) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(name=key, value=value))
    else:
        row.value = value


def servers(db: Session) -> list[dict]:
    return [dict(x) for x in _value(db, SERVERS_KEY).get("servers", [])]


def can_manage(s: Settings) -> bool:
    """dnsone-cluster.path is set up: the request directory exists and is ours to write."""
    d = s.cluster_request_dir
    return d.is_dir() and os.access(d, os.W_OK)


def status(s: Settings) -> dict:
    try:
        return json.loads((s.cluster_status_dir / "status.json").read_text())
    except (OSError, ValueError):
        return {}


def busy(s: Settings) -> bool:
    return (s.cluster_request_dir / REQUEST).exists() or status(s).get("state") == "running"


def overview(db: Session, s: Settings) -> dict:
    """Settings → Cluster: the servers added on this primary (never their passwords) and what dnsone-cluster did last."""
    ca = _value(db, CA_KEY).get("pem")
    rows = [{**{k: x.get(k) for k in ("address", "name", "state", "node", "message", "created")},
             "key_ready": x.get("state") == "ready" and bool(x.get("password") and ca)} for x in servers(db)]
    return {"servers": rows, "primary": _value(db, PRIMARY_KEY).get("address"), "can_manage": can_manage(s),
            "busy": busy(s), "status": status(s), "standalone": s.role == "primary" and not rows}


def _request(s: Settings, payload: dict) -> None:
    if not can_manage(s):
        raise ClusterError("Setting up the cluster from the console is not ready on this server yet: "
                           "update it once (Settings → Overview → Software update, or sudo dnsone-update).")
    if busy(s):
        raise ClusterError("A cluster change is under way on this server; wait for it to finish.")
    path = s.cluster_request_dir / REQUEST
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ClusterError("A cluster change is under way on this server; wait for it to finish.") from None
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({**payload, "id": secrets.token_hex(8), "at": utcnow().isoformat(timespec="seconds")}, f)


def _ip_field(raw: str, field: str) -> str:
    try:
        return _ipv4(raw)
    except ValueError:
        raise validation.ValidationError(field, "Enter the server's IPv4 address.") from None


def add_server(db: Session, address: str, name: str, listen: str) -> dict:
    """On the primary: prepares a new server (dnsone-cluster creates its account). Commits."""
    s = get_settings()
    if s.role != "primary":
        raise ClusterError("Servers are added on the primary.")
    address = _ip_field(address, "address")
    listen = _ip_field(listen, "listen")
    if address == listen:
        raise validation.ValidationError("address", "That is this server's own address.")
    items = servers(db)
    if any(x["address"] == address for x in items):
        raise validation.ValidationError("address", "This server is in the cluster already.")
    if not can_manage(s) or busy(s):
        _request(s, {})  # raises the reason
    entry = {"address": address, "name": name.strip()[:64], "state": "preparing", "password": secrets.token_hex(24),
             "created": utcnow().isoformat(timespec="seconds")}
    _put(db, SERVERS_KEY, {"servers": [*items, entry]})
    _put(db, PRIMARY_KEY, {"address": listen})
    set_secondaries(db, [*[x for x in secondaries(db) if x["address"] != address], {"address": address, "port": BIND_PORT, "name": entry["name"]}])
    firewall.refresh_cluster(db)
    db.commit()
    _request(s, {"action": "add", "address": address, "listen": listen, "password": entry["password"]})
    return entry


def join_key(db: Session, address: str) -> str:
    entry = next((x for x in servers(db) if x["address"] == address), None)
    ca = _value(db, CA_KEY).get("pem")
    primary = _value(db, PRIMARY_KEY).get("address")
    if entry is None or entry.get("state") != "ready" or not entry.get("password") or not ca or not primary:
        raise ClusterError("This server has no join key: it is not ready, or it joined already.")
    database, user = _account(get_settings().database_url)
    return make_key(primary, database, user, entry["password"], ca, address)


def remove_server(db: Session, address: str) -> dict:
    """On the primary: takes a server out (dnsone-cluster drops its account). Commits."""
    s = get_settings()
    items = servers(db)
    entry = next((x for x in items if x["address"] == address), None)
    if entry is None:
        raise ClusterError("This server is not in the cluster.")
    if not can_manage(s) or busy(s):
        _request(s, {})
    _put(db, SERVERS_KEY, {"servers": [x for x in items if x["address"] != address]})
    set_secondaries(db, [x for x in secondaries(db) if x["address"] != address])
    if entry.get("node"):
        row = db.get(Setting, f"node.{entry['node']}"[:64])
        if row is not None:
            db.delete(row)
    firewall.refresh_cluster(db)
    db.commit()
    _request(s, {"action": "remove", "address": address})
    return entry


def request_join(db: Session, text: str) -> dict:
    """On a standalone server: checks the key against the primary, then asks dnsone-cluster to join."""
    s = get_settings()
    if s.role != "primary":
        raise ClusterError("This server is in a cluster already.")
    if servers(db):
        raise ClusterError("Servers were added on this one: it is a primary. Remove them first to join another cluster.")
    key = parse_key(text)
    if not can_manage(s) or busy(s):
        _request(s, {})
    nodes = primary_nodes(key)
    if any(n.get("node") == s.node_name for n in nodes):
        raise ClusterError(f"A server named {s.node_name} is in that cluster already; each server needs its own name (DNSONE_NODE_NAME).")
    _request(s, {"action": "join", "key": "".join(text.split())})
    return {"primary": key["primary"], "address": key["address"]}


def request_leave() -> None:
    s = get_settings()
    if s.role != "replica":
        raise ClusterError("This server is not a replica.")
    _request(s, {"action": "leave"})


# --------------------------------------------------------------------------- configuration files (pure)


def add_listen(text: str, address: str, port: int = BIND_PORT) -> str:
    """named.conf.options with `address` in its `listen-on port <port> { … };`."""
    found = False

    def repl(m: re.Match) -> str:
        nonlocal found
        if int(m.group(2)) != port:
            return m.group(0)
        found = True
        items = [x.strip() for x in m.group(3).split(";") if x.strip()]
        if address in items:
            return m.group(0)
        return f"{m.group(1)} {' '.join(f'{x};' for x in [*items, address])} {m.group(4)}"

    out = LISTEN.sub(repl, text)
    if not found:
        raise ClusterError(f"named.conf.options has no `listen-on port {port} {{ … }};` line.")
    return out


def remove_block(text: str) -> str:
    return re.sub(rf"\n?[ \t]*{re.escape(BEGIN)}\n.*?{re.escape(END)}\n", "\n", text, flags=re.S)


def set_block(text: str, lines: list[str]) -> str:
    """named.conf.options with DNSOne's lines (between markers) first in `options { }`."""
    text = remove_block(text)
    m = re.search(r"^[ \t]*options\s*\{[^\n]*\n", text, flags=re.M)
    if not m:
        raise ClusterError("named.conf.options has no `options {` block.")
    block = "\n".join(f"    {line}" for line in [BEGIN, *lines, END]) + "\n"
    return text[:m.end()] + block + text[m.end():]


def catalog_lines(catalog: str, primary: str, catalog_dir: Path) -> list[str]:
    return ["catalog-zones {",
            f'    zone "{catalog}" default-primaries {{ {primary} port {BIND_PORT}; }} zone-directory "{catalog_dir}";',
            "};"]


def render_cluster_conf(catalog: str | None = None, primary: str | None = None, catalog_dir: Path | None = None) -> str:
    head = "// Written by DNSOne (Settings → Cluster). Do not edit: joining or leaving a cluster rewrites it.\n"
    if not primary:
        return head + "// This server is not a replica.\n"
    return head + ("// This server is a replica: its BIND follows the primary's catalog zone.\n"
                   f'zone "{catalog}" {{\n    type secondary;\n    primaries {{ {primary} port {BIND_PORT}; }};\n'
                   f'    file "{catalog_dir}/{catalog}.db";\n}};\n')


def set_env(text: str, values: dict[str, str]) -> str:
    lines = text.splitlines()
    for key, value in values.items():
        for i, line in enumerate(lines):
            if line.split("=", 1)[0].strip() == key:
                lines[i] = f"{key}={value}"
                break
        else:
            lines.append(f"{key}={value}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- dnsone-cluster (root)


def run_command(cmd: list[str], stdin: str | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=COMMAND_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


class Applier:
    def __init__(self, s: Settings, paths: Paths = PATHS):
        self.s = s
        self.paths = paths
        self.lines: list[str] = []
        self.request: dict = {}
        self.started = utcnow().isoformat(timespec="seconds")

    # ------------------------------------------------------------------ progress

    def write_status(self, state: str, message: str = "") -> None:
        d = self.s.cluster_status_dir
        d.mkdir(parents=True, exist_ok=True)
        body = {"id": self.request.get("id"), "action": self.request.get("action"), "state": state, "message": message,
                "started": self.started, "finished": utcnow().isoformat(timespec="seconds") if state != "running" else None,
                "log": "\n".join(self.lines)[-32_000:]}
        tmp = d / ".status.json.new"
        tmp.write_text(json.dumps(body))
        os.chmod(tmp, 0o640)
        try:
            shutil.chown(tmp, group="dnsone")
        except (LookupError, OSError):
            pass
        os.replace(tmp, d / "status.json")

    def step(self, text: str) -> None:
        log.info("cluster: %s", text)
        self.lines.append(f"== {text}")
        self.write_status("running")

    def cmd(self, cmd: list[str], stdin: str | None = None, check: bool = True) -> tuple[int, str]:
        code, out = run_command(cmd, stdin)
        shown = " ".join(cmd)
        self.lines.append(f"$ {shown}" + (f"\n{out}" if out else "") + (f"\n(exit {code})" if code else ""))
        if check and code != 0:
            raise ClusterError(f"{shown} failed: {out[-500:] or f'exit {code}'}")
        return code, out

    def ufw_active(self) -> bool:
        code, out = run_command(["ufw", "status"])
        return code == 0 and out.startswith("Status: active")

    @staticmethod
    def write(path: Path, text: str, mode: int = 0o644, like: Path | None = None) -> None:
        """Replaces a file atomically, with the owner and mode of the file it replaces (or `like`)."""
        ref = path if path.exists() else like
        tmp = path.with_name(f".{path.name}.dnsone-new")
        tmp.write_text(text)
        if ref is not None and ref.exists():
            st = ref.stat()
            os.chmod(tmp, st.st_mode & 0o7777)
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except OSError:
                pass
        else:
            os.chmod(tmp, mode)
        os.replace(tmp, path)

    def save(self, paths: list[Path]) -> dict[Path, str | None]:
        return {p: (p.read_text() if p.exists() else None) for p in paths}

    def restore(self, saved: dict[Path, str | None]) -> None:
        for path, text in saved.items():
            if text is None:
                path.unlink(missing_ok=True)
            elif not path.exists() or path.read_text() != text:
                self.write(path, text)

    def mark(self, conn: pymysql.connections.Connection, address: str, **values) -> None:
        """Updates a server's entry in cluster.servers (in the database `conn` reaches); None removes a field."""
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM settings WHERE name = %s FOR UPDATE", (SERVERS_KEY,))
            row = cur.fetchone()
            if row is None:
                conn.rollback()
                return
            data = json.loads(row[0]) if isinstance(row[0], (str, bytes)) else row[0]
            for entry in data.get("servers", []):
                if entry.get("address") == address:
                    entry.update(values)
                    for k in [k for k, v in entry.items() if v is None]:
                        del entry[k]
            cur.execute("UPDATE settings SET value = %s WHERE name = %s", (json.dumps(data), SERVERS_KEY))
        conn.commit()

    def local_db(self) -> pymysql.connections.Connection:
        """This server's own database (DNSONE_DATABASE_URL as dnsone.env had it when this run started)."""
        url = make_url(self.s.database_url)
        ssl = {"ca": url.query["ssl_ca"], "check_hostname": False} if url.query.get("ssl_ca") else None
        return pymysql.connect(host=url.host or "127.0.0.1", port=url.port or MYSQL_PORT, user=url.username, password=url.password or "",
                               database=url.database, ssl=ssl, connect_timeout=10, charset="utf8mb4")

    def restart_dnsone(self) -> None:
        units = ["dnsone-api", "dnsone-querylog"]
        if run_command(["systemctl", "is-enabled", "--quiet", "dnsone-ddns"])[0] == 0:
            units.append("dnsone-ddns")
        self.cmd(["systemctl", "restart", *units])

    # ------------------------------------------------------------------ actions

    def apply(self) -> int:
        path = self.s.cluster_request_dir / REQUEST
        try:
            raw = path.read_text()
        except OSError:
            return 0
        finally:
            path.unlink(missing_ok=True)
        try:
            self.request = json.loads(raw)
            action = {"add": self.add, "remove": self.remove, "join": self.join, "leave": self.leave}[self.request["action"]]
        except (ValueError, KeyError, TypeError):
            self.write_status("failed", "The request was not understood; nothing changed.")
            return 1
        self.write_status("running")
        try:
            message = action()
        except (ClusterError, validation.ValidationError, ValueError, KeyError, OSError, pymysql.MySQLError) as exc:
            log.exception("cluster: %s failed", self.request.get("action"))
            self.lines.append(f"FAILED: {exc}")
            self.write_status("failed", str(exc))
            if self.request.get("action") == "add":
                self.record_add_failure(str(exc))
            return 1
        self.lines.append(message)
        self.write_status("done", message)
        return 0

    def record_add_failure(self, message: str) -> None:
        try:
            conn = self.local_db()
            try:
                self.mark(conn, str(self.request.get("address")), state="failed", message=message[:500])
            finally:
                conn.close()
        except pymysql.MySQLError:
            log.exception("cluster: cannot record the failure")

    def add(self) -> str:
        """On the primary: an account, MySQL and BIND reachable, ufw open, the CA stored."""
        address, listen = _ipv4(self.request["address"]), _ipv4(self.request["listen"])
        password = str(self.request["password"])
        if not PASSWORD.match(password):
            raise ClusterError("The request's password is not valid; nothing changed.")
        database, user = _account(self.s.database_url)
        self.step(f"MySQL: an account for {address} (TLS only)")
        self.cmd(["mysql", "--batch"], stdin=(
            f"CREATE USER IF NOT EXISTS '{user}'@'{address}' IDENTIFIED BY '{password}' REQUIRE SSL;\n"
            f"ALTER USER '{user}'@'{address}' IDENTIFIED BY '{password}' REQUIRE SSL;\n"
            f"GRANT ALL PRIVILEGES ON `{database}`.* TO '{user}'@'{address}';\n"))

        self.step(f"MySQL: listening on {listen}")
        cnf = ("# Written by DNSOne (Settings → Cluster): the cluster's servers reach MySQL on this address.\n"
               f"[mysqld]\nbind-address = 127.0.0.1,{listen}\n")
        if not self.paths.mysql_cnf.exists() or self.paths.mysql_cnf.read_text() != cnf:
            self.write(self.paths.mysql_cnf, cnf)
            self.cmd(["systemctl", "restart", "mysql"])
            for _ in range(60):
                if run_command(["mysqladmin", "ping"])[0] == 0:
                    break
                time.sleep(1)
            else:
                raise ClusterError("MySQL did not come back after its restart; see journalctl -u mysql.")
        else:
            self.lines.append("already so")

        self.step(f"BIND: listening on {listen}:{BIND_PORT}")
        before = self.paths.named_options.read_text()
        after = add_listen(before, listen)
        if after != before:
            self.write(self.paths.named_options, after)
            if self.cmd(["named-checkconf"], check=False)[0] != 0:
                self.write(self.paths.named_options, before)
                raise ClusterError("named-checkconf refused named.conf.options with the address; it is unchanged.")
            self.cmd(["rndc", "reconfig"])
        else:
            self.lines.append("already so")

        if self.ufw_active():
            self.step(f"ufw: MySQL and BIND open to {address}")
            self.cmd(["ufw", "allow", "from", address, "to", "any", "port", str(MYSQL_PORT), "proto", "tcp"])
            self.cmd(["ufw", "allow", "from", address, "to", "any", "port", str(BIND_PORT)])

        self.step("The join key")
        ca = clean_pem(self.paths.mysql_ca.read_text()) if self.paths.mysql_ca.exists() else ""
        if not PEM.match(ca):
            raise ClusterError(f"MySQL has no CA certificate in {self.paths.mysql_ca} (it makes one when it starts with TLS on).")
        conn = self.local_db()
        try:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO settings (name, value) VALUES (%s, %s) ON DUPLICATE KEY UPDATE value = VALUES(value)",
                            (CA_KEY, json.dumps({"pem": ca})))
            conn.commit()
            self.mark(conn, address, state="ready", message=None)
        finally:
            conn.close()
        return f"{address} is ready to join: its join key is in Settings → Cluster."

    def remove(self) -> str:
        address = _ipv4(self.request["address"])
        _, user = _account(self.s.database_url)
        self.step(f"MySQL: the account for {address} removed")
        self.cmd(["mysql", "--batch"], stdin=f"DROP USER IF EXISTS '{user}'@'{address}';\n")
        if self.ufw_active():
            self.step(f"ufw: MySQL and BIND closed to {address}")
            self.cmd(["ufw", "delete", "allow", "from", address, "to", "any", "port", str(MYSQL_PORT), "proto", "tcp"], check=False)
            self.cmd(["ufw", "delete", "allow", "from", address, "to", "any", "port", str(BIND_PORT)], check=False)
        return f"{address} is out of the cluster."

    def join(self) -> str:
        p = self.paths
        key = parse_key(self.request["key"])
        if self.s.role != "primary":
            raise ClusterError("This server is in a cluster already.")
        self.step(f"The primary's database at {key['primary']}")
        nodes = primary_nodes(key)
        if any(n.get("node") == self.s.node_name for n in nodes):
            raise ClusterError(f"A server named {self.s.node_name} is in that cluster already.")
        self.lines.append(f"reached; DNSOne {__version__} on both")

        saved = self.save([p.env, p.ca, p.named_options, p.named_local, p.cluster_conf, p.zones_conf,
                           standalone(p.env), standalone(p.zones_conf)])
        try:
            self.step("DNSOne: the primary's database, as a replica")
            self.write(p.ca, key["ca"], 0o644)
            if not standalone(p.env).exists():
                shutil.copy2(p.env, standalone(p.env))
            self.write(p.env, set_env(p.env.read_text(), {"DNSONE_DATABASE_URL": database_url(key, p.ca), "DNSONE_ROLE": "replica"}))

            self.step(f"BIND: a secondary of {key['primary']} (catalog {self.s.catalog_zone})")
            options = set_block(p.named_options.read_text(), catalog_lines(self.s.catalog_zone, key["primary"], p.catalog_dir))
            self.write(p.named_options, add_listen(options, key["address"]))
            self.write(p.cluster_conf, render_cluster_conf(self.s.catalog_zone, key["primary"], p.catalog_dir), like=p.named_local)
            include = f'include "{p.cluster_conf}";'
            local = p.named_local.read_text()
            if include not in local:
                self.write(p.named_local, local.rstrip("\n") + f"\n\n// The primary's catalog zone on a replica (Settings → Cluster).\n{include}\n")
            if p.zones_conf.exists() and not standalone(p.zones_conf).exists():
                shutil.copy2(p.zones_conf, standalone(p.zones_conf))
            self.write(p.zones_conf, "// This server is a replica (Settings → Cluster): its zones come from the primary's catalog.\n", like=p.named_local)
            p.catalog_dir.mkdir(parents=True, exist_ok=True)
            try:
                shutil.chown(p.catalog_dir, "bind", "bind")
            except (LookupError, OSError):
                pass
            self.cmd(["named-checkconf"])
            self.cmd(["systemctl", "restart", "named"])
            if self.ufw_active():
                self.cmd(["ufw", "allow", "from", key["primary"], "to", "any", "port", str(BIND_PORT)])

            self.step("DNSOne: restart and sync")
            self.restart_dnsone()
            self.cmd(["systemctl", "start", "dnsone-sync.service"], check=False)
        except (ClusterError, OSError, ValueError) as exc:
            self.lines.append(f"Putting the standalone configuration back: {exc}")
            self.restore(saved)
            self.cmd(["systemctl", "restart", "named"], check=False)
            self.cmd(["systemctl", "restart", "dnsone-api", "dnsone-querylog"], check=False)
            raise

        conn = connect(key)
        try:
            self.mark(conn, key["address"], state="joined", node=self.s.node_name, password=None, message=None)
        finally:
            conn.close()
        return f"This server is a replica of {key['primary']}. Sign in with the primary's accounts."

    def leave(self) -> str:
        p = self.paths
        if self.s.role != "replica":
            raise ClusterError("This server is not a replica.")
        if not standalone(p.env).exists():
            raise ClusterError(f"{standalone(p.env)} is missing: this server did not join from the console, so it cannot leave from it.")
        try:
            conn = self.local_db()
            try:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM settings WHERE name = %s", (f"node.{self.s.node_name}"[:64],))
                    cur.execute("SELECT value FROM settings WHERE name = %s", (SERVERS_KEY,))
                    row = cur.fetchone()
                conn.commit()
                data = json.loads(row[0]) if row else {}
                for entry in data.get("servers", []):
                    if entry.get("node") == self.s.node_name:
                        self.mark(conn, entry["address"], state="left", message="Left the cluster; remove it here.")
            finally:
                conn.close()
        except pymysql.MySQLError as exc:
            self.lines.append(f"(the primary's database was not told: {exc})")

        saved = self.save([p.env, p.named_options, p.cluster_conf, p.zones_conf])
        try:
            self.step("DNSOne: this server's own database again")
            self.write(p.env, standalone(p.env).read_text())
            self.step("BIND: its own zones again")
            self.write(p.named_options, remove_block(p.named_options.read_text()))
            if p.cluster_conf.exists():
                self.write(p.cluster_conf, render_cluster_conf())
            if standalone(p.zones_conf).exists():
                self.write(p.zones_conf, standalone(p.zones_conf).read_text())
            self.cmd(["named-checkconf"])
            self.cmd(["systemctl", "restart", "named"])
            self.step("DNSOne: restart and sync")
            self.restart_dnsone()
            self.cmd(["systemctl", "start", "dnsone-sync.service"], check=False)
        except (ClusterError, OSError, ValueError) as exc:
            self.lines.append(f"Putting the replica configuration back: {exc}")
            self.restore(saved)
            self.cmd(["systemctl", "restart", "named"], check=False)
            self.cmd(["systemctl", "restart", "dnsone-api", "dnsone-querylog"], check=False)
            raise
        standalone(p.env).unlink(missing_ok=True)
        standalone(p.zones_conf).unlink(missing_ok=True)
        return "This server runs on its own again, with its own database."


def main(argv: list[str] | None = None) -> int:
    # To the journal only: a file root opened in /var/log/dnsone could end up owned by root.
    logging.basicConfig(level=logging.INFO, format="dnsone-cluster: %(levelname)s %(message)s")
    args = argv if argv is not None else sys.argv[1:]
    if args != ["apply"]:
        print("usage: python -m dnsone.clusterjoin apply", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("dnsone-cluster runs as root", file=sys.stderr)
        return 1
    return Applier(get_settings()).apply()


if __name__ == "__main__":
    sys.exit(main())
