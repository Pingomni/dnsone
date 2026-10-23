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

    # PowerDNS Recursor
    recursor_forward_zones_file: Path
    recursor_nta_file: Path
    rec_control: list[str]
    recursor_api_url: str
    recursor_api_key: str
    # Generated for the Recursor's DNSOne policy script and ACL (see runtime.py).
    recursor_policy_file: Path
    recursor_allow_from_file: Path

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

    # Single sign-on (Keycloak, OpenID Connect). Off while oidc_issuer is empty.
    oidc_issuer: str
    oidc_client_id: str
    oidc_client_secret: str
    # The console's public URL (https://dns.example): the callback is <public_url>/api/auth/oidc/callback.
    public_url: str
    oidc_label: str
    # Keycloak role -> DNSOne role, highest first (realm roles or roles of the client).
    oidc_roles: tuple[tuple[str, str], ...]
    # Keycloak's admin API, for Settings -> Single sign-on: Keycloak reached directly (not through
    # nginx), its realm, and the service-account client DNSOne manages users and settings with.
    keycloak_url: str
    keycloak_realm: str
    keycloak_admin_client_id: str
    keycloak_admin_client_secret: str
    # Password sign-in with DNSOne's own accounts. Off once SSO is the way in; the emergency link
    # (dnsone-ctl emergency-login) still works.
    local_login: bool

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
        recursor_forward_zones_file=Path(_env("RECURSOR_FORWARD_ZONES_FILE", "/var/lib/dnsone/recursor/forward-zones.conf")),
        recursor_nta_file=Path(_env("RECURSOR_NTA_FILE", "/var/lib/dnsone/recursor/negative-trust-anchors.txt")),
        rec_control=shlex.split(_env("REC_CONTROL", "/usr/bin/sudo -n -u pdns /usr/bin/rec_control")),
        recursor_api_url=_env("RECURSOR_API_URL", "http://127.0.0.1:8082").rstrip("/"),
        recursor_api_key=_env("RECURSOR_API_KEY"),
        recursor_policy_file=Path(_env("RECURSOR_POLICY_FILE", "/var/lib/dnsone/recursor/policy.lua")),
        recursor_allow_from_file=Path(_env("RECURSOR_ALLOW_FROM_FILE", "/var/lib/dnsone/recursor/allow-from.conf")),
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
        oidc_issuer=_env("OIDC_ISSUER").rstrip("/"),
        oidc_client_id=_env("OIDC_CLIENT_ID", "dnsone"),
        oidc_client_secret=_env("OIDC_CLIENT_SECRET"),
        public_url=_env("PUBLIC_URL").rstrip("/"),
        oidc_label=_env("OIDC_LABEL", "Sign in with SSO"),
        oidc_roles=tuple(
            (k.strip(), v.strip()) for k, _, v in (pair.partition("=") for pair in
            _env("OIDC_ROLES", "dnsone-admin=admin,dnsone-operator=operator,dnsone-viewer=viewer").split(",")) if k.strip() and v.strip()
        ),
        keycloak_url=_env("KEYCLOAK_URL", "http://127.0.0.1:8180/auth").rstrip("/"),
        keycloak_realm=_env("KEYCLOAK_REALM", "pingomni"),
        keycloak_admin_client_id=_env("KEYCLOAK_ADMIN_CLIENT_ID", "dnsone-admin-api"),
        keycloak_admin_client_secret=_env("KEYCLOAK_ADMIN_CLIENT_SECRET"),
        local_login=_bool("LOCAL_LOGIN", True),
        log_file=Path(log_file) if log_file else None,
        log_level=_env("LOG_LEVEL", "INFO").upper(),
        frontend_dist=Path(frontend) if frontend else None,
        command_timeout=_int("COMMAND_TIMEOUT", 60),
    )
