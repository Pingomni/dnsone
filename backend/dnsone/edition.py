"""Editions: DNSOne Community is DNSOne without the Pro modules (tools/export-community.sh leaves them out).

Everything else imports a Pro module through pro(), which gives None when it is not installed, and then
does what Community does: no attack protection, firewall, zone transfers, quotas, court orders, single
sign-on, query log export or cluster management. The database schema is the same in both editions, so
a Community server can move to Pro by installing it over the top.
"""
from __future__ import annotations

import importlib
from types import ModuleType

# The Pro modules, each with what it adds (shown under Settings → Overview and in /api/auth/me).
PRO = {
    "protection": "Attack protection",
    "firewall": "Firewall",
    "transfers": "Zone transfers to secondaries",
    "quota": "Customer quotas",
    "legal": "Court-ordered blocking",
    "oidc": "Single sign-on",
    "logexport": "Query log export",
    "api.cluster": "Cluster management",
}


def pro(name: str) -> ModuleType | None:
    """dnsone.<name> if this edition has it, else None."""
    try:
        return importlib.import_module(f"{__package__}.{name}")
    except ModuleNotFoundError as exc:
        if exc.name != f"{__package__}.{name}":
            raise  # the module is there but something it imports is missing: a real error
        return None


def features() -> list[str]:
    """The Pro modules installed (the console shows their pages only when they are)."""
    return [name.removeprefix("api.") for name in PRO if pro(name) is not None]


def name() -> str:
    return "pro" if len(features()) == len(PRO) else "community"
