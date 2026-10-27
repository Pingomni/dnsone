"""Runtime settings, read once from the environment (systemd loads /etc/dnsone/dnsone.env).

Every variable is prefixed DNSONE_. Paths default to the layout the runbook installs, so a
production env file only needs the secrets and the node's addresses.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"DNSONE_{name}", default).strip()


def _bool(name: str, default: bool) -> bool:
    raw = _env(name, "1" if default else "0").lower()
    return raw in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    raw = _env(name, str(default))
    try:
        return int(raw)
    except ValueError as exc:
        raise RuntimeError(f"DNSONE_{name} must be an integer, got {raw!r}") from exc


def _choice(name: str, default: str, allowed: tuple[str, ...]) -> str:
    value = _env(name, default).lower()
    if value not in allowed:
        raise RuntimeError(f"DNSONE_{name} must be one of {', '.join(allowed)}, got {value!r}")
    return value


@dataclass(frozen=True)
class Settings:
    database_url: str
    node_name: str
    timezone: str
    # primary: publishes zones (BIND primary). replica: resolver only; zones arrive by transfer.
    role: str

    # Sessions
    session_hours: int
    cookie_secure: bool
    login_max_failures: int
    login_lock_minutes: int

    # BIND
    zones_dir: Path
    bind_zones_conf: Path
    named_conf: Path
    named_checkzone: str
    named_checkconf: str
    rndc: str
    rndc_key: Path
    rndc_server: str
    rndc_port: int
    bind_address: str
    bind_port: int
    # Phase 2: the catalog zone listing hosted zones for BIND secondaries.
    catalog_zone: str
    # DNSSEC: where BIND keeps the signing keys of zones DNSOne has it sign (written by BIND, not DNSOne).
    bind_key_dir: Path
    # DNSSEC policy timings in seconds (BIND's defaults): how long BIND waits before it trusts that a
    # new DNSKEY or DS has reached every resolver, which is when it publishes CDS and moves a rollover on.
    dnssec_dnskey_ttl: int
    dnssec_publish_safety: int
    dnssec_propagation_delay: int
    dnssec_parent_ds_ttl: int
    dnssec_parent_propagation_delay: int
    # The policy's max-zone-ttl: the longest TTL a signed zone may hold. BIND waits this long after
    # signing a zone before it publishes CDS (old unsigned answers must have left every cache).
    dnssec_max_zone_ttl: int

    # PowerDNS Recursor
    recursor_forward_zones_file: Path
    recursor_nta_file: Path
    rec_control: list[str]
    recursor_api_url: str
    recursor_api_key: str
    # Generated for the Recursor's DNSOne policy script and ACL (see runtime.py).
    recursor_policy_file: Path
    recursor_allow_from_file: Path
    # Generated: Settings → DNS server → Resolver (ECS, serve-stale), read through recursor.conf's
    # include-dir; the Recursor reads it only at start, so a change restarts it with this command.
    recursor_settings_file: Path
    recursor_restart: list[str]

    # dnsdist
    dnsdist_auth_zones_file: Path
    dnsdist_api_url: str
    dnsdist_api_key: str
    # Generated: client networks, NAT addresses, rate limits, regex rules (dnsdist re-reads it).
    dnsdist_settings_file: Path
    # Phase 1 kept client networks here; read once as the initial value of Settings → DNS server.
    legacy_client_networks_file: Path

    # RPZ
    rpz_zone: str
    rpz_file: Path
    blocklist_dir: Path
    blocklist_max_bytes: int
    blocklist_timeout: int

    # Query log (dnsone-querylog)
    querylog_mode: str
    querylog_listen: str
    querylog_retention_hours: int
    querylog_max_rows: int
    querylog_ignore_clients: frozenset[str]

    # ALIAS records: resolvers for targets outside the hosted zones (empty: /etc/resolv.conf).
    alias_resolvers: tuple[str, ...]

    # Dynamic DNS (dnsone-ddns): where dnsdist sends RFC 2136 updates.
    ddns_listen: str

    # Software update (Settings → Overview): the GitHub repository releases come from, whether the
    # console asks GitHub for them, where it leaves an install request (for dnsone-update.path) and
    # where dnsone-update (root) writes its progress.
    update_repo: str
    update_check: bool
    update_request_dir: Path
    update_status_dir: Path
    # The PingOmni account portal, where the licence's server is registered (activation.py); empty: off.
    account_url: str
    # The machine's ID: registration (activation.py) and the licence's server ID (license.server_id()) derive from it.
    machine_id_file: Path

    # Firewall (Settings → Firewall): the API leaves an apply request in firewall_request_dir, which
    # dnsone-firewall.path sees; dnsone-firewall (root) applies it and writes firewall_status_dir.
    firewall_request_dir: Path
    firewall_status_dir: Path

    # Cluster set-up (Settings → Cluster): the API leaves a request in cluster_request_dir, which
    # dnsone-cluster.path sees; dnsone-cluster (root) carries it out and writes cluster_status_dir.
    cluster_request_dir: Path
    cluster_status_dir: Path

    # Logging
    log_file: Path | None
    log_level: str

    # Paths the frontend is served from when nginx is not in front (development).
    frontend_dist: Path | None

    command_timeout: int = 60


def _load_env_file() -> None:
    """Reads /etc/dnsone/dnsone.env (or DNSONE_ENV_FILE) for variables not already set.

    systemd passes the file with EnvironmentFile=; this makes `dnsone-ctl` work from a shell too.
    """
    path = Path(os.environ.get("DNSONE_ENV_FILE", "/etc/dnsone/dnsone.env"))
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    _load_env_file()
    database_url = _env("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DNSONE_DATABASE_URL is not set (see /etc/dnsone/dnsone.env)")
    log_file = _env("LOG_FILE", "/var/log/dnsone/dnsone.log")
    frontend = _env("FRONTEND_DIST")
    return Settings(
        database_url=database_url,
        node_name=_env("NODE_NAME", os.uname().nodename)[:64],
        timezone=_env("TIMEZONE", "UTC"),
        role=_choice("ROLE", "primary", ("primary", "replica")),
        session_hours=_int("SESSION_HOURS", 12),
        cookie_secure=_bool("COOKIE_SECURE", True),
        login_max_failures=_int("LOGIN_MAX_FAILURES", 5),
        login_lock_minutes=_int("LOGIN_LOCK_MINUTES", 15),
        zones_dir=Path(_env("ZONES_DIR", "/var/lib/bind/zones")),
        bind_zones_conf=Path(_env("BIND_ZONES_CONF", "/etc/bind/dnsone/zones.conf")),
        named_conf=Path(_env("NAMED_CONF", "/etc/bind/named.conf")),
        named_checkzone=_env("NAMED_CHECKZONE", "/usr/bin/named-checkzone"),
        named_checkconf=_env("NAMED_CHECKCONF", "/usr/bin/named-checkconf"),
        rndc=_env("RNDC", "/usr/sbin/rndc"),
        rndc_key=Path(_env("RNDC_KEY", "/etc/bind/dnsone/dnsone-rndc.key")),
        rndc_server=_env("RNDC_SERVER", "127.0.0.1"),
        rndc_port=_int("RNDC_PORT", 953),
        bind_address=_env("BIND_ADDRESS", "127.0.0.1"),
        bind_port=_int("BIND_PORT", 5301),
        catalog_zone=_env("CATALOG_ZONE", "catalog.dnsone").rstrip("."),
        bind_key_dir=Path(_env("BIND_KEY_DIR", "/var/lib/bind/keys")),
        dnssec_dnskey_ttl=_int("DNSSEC_DNSKEY_TTL", 3600),
        dnssec_publish_safety=_int("DNSSEC_PUBLISH_SAFETY", 3600),
        dnssec_propagation_delay=_int("DNSSEC_PROPAGATION_DELAY", 300),
        dnssec_parent_ds_ttl=_int("DNSSEC_PARENT_DS_TTL", 86400),
        dnssec_parent_propagation_delay=_int("DNSSEC_PARENT_PROPAGATION_DELAY", 3600),
        dnssec_max_zone_ttl=_int("DNSSEC_MAX_ZONE_TTL", 604800),
        recursor_forward_zones_file=Path(_env("RECURSOR_FORWARD_ZONES_FILE", "/var/lib/dnsone/recursor/forward-zones.conf")),
        recursor_nta_file=Path(_env("RECURSOR_NTA_FILE", "/var/lib/dnsone/recursor/negative-trust-anchors.txt")),
        rec_control=shlex.split(_env("REC_CONTROL", "/usr/bin/sudo -n -u pdns /usr/bin/rec_control")),
        recursor_api_url=_env("RECURSOR_API_URL", "http://127.0.0.1:8082").rstrip("/"),
        recursor_api_key=_env("RECURSOR_API_KEY"),
        recursor_policy_file=Path(_env("RECURSOR_POLICY_FILE", "/var/lib/dnsone/recursor/policy.lua")),
        recursor_allow_from_file=Path(_env("RECURSOR_ALLOW_FROM_FILE", "/var/lib/dnsone/recursor/allow-from.conf")),
        recursor_settings_file=Path(_env("RECURSOR_SETTINGS_FILE", "/var/lib/dnsone/recursor/conf.d/dnsone.conf")),
        recursor_restart=shlex.split(_env("RECURSOR_RESTART", "/usr/bin/sudo -n /usr/bin/systemctl restart pdns-recursor")),
        dnsdist_auth_zones_file=Path(_env("DNSDIST_AUTH_ZONES_FILE", "/var/lib/dnsone/dnsdist/auth-zones.txt")),
        dnsdist_api_url=_env("DNSDIST_API_URL", "http://127.0.0.1:8083").rstrip("/"),
        dnsdist_api_key=_env("DNSDIST_API_KEY"),
        dnsdist_settings_file=Path(_env("DNSDIST_SETTINGS_FILE", "/var/lib/dnsone/dnsdist/settings.lua")),
        legacy_client_networks_file=Path(_env("CLIENT_NETWORKS_FILE", "/etc/dnsone/client-networks.conf")),
        rpz_zone=_env("RPZ_ZONE", "rpz.dnsone").rstrip("."),
        rpz_file=Path(_env("RPZ_FILE", "/var/lib/dnsone/rpz/dnsone.rpz")),
        blocklist_dir=Path(_env("BLOCKLIST_DIR", "/var/lib/dnsone/blocklists")),
        blocklist_max_bytes=_int("BLOCKLIST_MAX_BYTES", 64 * 1024 * 1024),
        blocklist_timeout=_int("BLOCKLIST_TIMEOUT", 60),
        querylog_mode=_choice("QUERYLOG_MODE", "full", ("full", "aggregate", "off")),
        querylog_listen=_env("QUERYLOG_LISTEN", "127.0.0.1:4242"),
        querylog_retention_hours=_int("QUERYLOG_RETENTION_HOURS", 24),
        querylog_max_rows=_int("QUERYLOG_MAX_ROWS", 20_000_000),
        querylog_ignore_clients=frozenset(c.strip() for c in _env("QUERYLOG_IGNORE_CLIENTS", "127.0.0.1,::1").split(",") if c.strip()),
        alias_resolvers=tuple(a.strip() for a in _env("ALIAS_RESOLVERS").split(",") if a.strip()),
        ddns_listen=_env("DDNS_LISTEN", "127.0.0.1:5302"),
        update_repo=_env("UPDATE_REPO", "Pingomni/dnsone"),
        update_check=_bool("UPDATE_CHECK", True),
        update_request_dir=Path(_env("UPDATE_REQUEST_DIR", "/var/lib/dnsone/update")),
        update_status_dir=Path(_env("UPDATE_STATUS_DIR", "/var/lib/dnsone/update-status")),
        account_url=_env("ACCOUNT_URL", "https://account.pingomni.com").rstrip("/"),
        machine_id_file=Path(_env("MACHINE_ID_FILE", "/etc/machine-id")),
        firewall_request_dir=Path(_env("FIREWALL_REQUEST_DIR", "/var/lib/dnsone/firewall")),
        firewall_status_dir=Path(_env("FIREWALL_STATUS_DIR", "/var/lib/dnsone/firewall-status")),
        cluster_request_dir=Path(_env("CLUSTER_REQUEST_DIR", "/var/lib/dnsone/cluster")),
        cluster_status_dir=Path(_env("CLUSTER_STATUS_DIR", "/var/lib/dnsone/cluster-status")),
        log_file=Path(log_file) if log_file else None,
        log_level=_env("LOG_LEVEL", "INFO").upper(),
        frontend_dist=Path(frontend) if frontend else None,
        command_timeout=_int("COMMAND_TIMEOUT", 60),
    )
