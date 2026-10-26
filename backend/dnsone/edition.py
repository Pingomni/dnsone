"""Editions: the Pro features of DNSOne are on where a licence allows them (license.py), and DNSOne works as
DNSOne Community where none does.

Everything else uses a Pro module through pro(name): a stand-in that is true while the licence lets the
feature run, and passes everything else on to the module. Without a licence every caller does what
Community does: no attack protection, firewall, zone transfers, quotas, court orders, single sign-on,
query log export or cluster management. The database schema is the same either way, so adding or removing
a licence never needs a migration.
"""
from __future__ import annotations

import importlib
from functools import cache
from types import ModuleType

from fastapi import Request

from . import license

# The Pro modules and their features (licence feature names), with what each adds.
PRO = {
    "protection": ("protection", "Attack protection"),
    "firewall": ("firewall", "Firewall"),
    "transfers": ("transfers", "Zone transfers to secondaries"),
    "quota": ("quota", "Customer quotas and resellers"),
    "legal": ("legal", "Court-ordered blocking"),
    "oidc": ("oidc", "Single sign-on"),
    "logexport": ("logexport", "Query log export"),
    "api.cluster": ("cluster", "Cluster management"),
    "api.protection": ("protection", "Attack protection"),
    "api.firewall": ("firewall", "Firewall"),
    "api.transfers": ("transfers", "Zone transfers to secondaries"),
    "api.legal": ("legal", "Court-ordered blocking"),
}


class Pro:
    """A Pro module, behind its licence: true while the feature may run; .writable while it may be changed."""

    def __init__(self, name: str):
        self._name = name
        self._feature = PRO[name][0]

    @property
    def module(self) -> ModuleType:
        return importlib.import_module(f"{__package__}.{self._name}")

    @property
    def feature(self) -> str:
        return self._feature

    @property
    def writable(self) -> bool:
        return license.allows(self._feature, write=True)

    def __bool__(self) -> bool:
        return license.allows(self._feature)

    def __getattr__(self, attr: str):
        return getattr(self.module, attr)


@cache
def pro(name: str) -> Pro:
    """The Pro module dnsone.<name>, behind its licence."""
    return Pro(name)


def features() -> list[str]:
    """The Pro features this server's licence lets run."""
    return list(license.current()["features"]) if license.current()["state"] != "none" else []


def name() -> str:
    return "pro" if features() else "community"


# What each licence feature is called in the console.
FEATURE_NAMES = {feature: label for feature, label in PRO.values()}

MISSING = "{label} is part of DNSOne Pro: add a licence under Settings → License."
EXPIRED = "Your DNSOne Pro licence has expired, so {label} can be viewed but not changed: renew it under Settings → License."


def require(module: Pro, label: str, write: bool = False) -> None:
    """For an API call: 404 where the licence does not have the feature, 402 for a change once it expired."""
    from .api.deps import ApiError
    if not module:
        raise ApiError(404, MISSING.format(label=label))
    if write and not module.writable:
        raise ApiError(402, EXPIRED.format(label=label))


def guard(feature: str):
    """A FastAPI dependency for a Pro router: reads need the feature, changes a licence that has not expired."""
    label = FEATURE_NAMES[feature]

    def check(request: Request) -> None:
        write = request.method not in ("GET", "HEAD", "OPTIONS")
        from .api.deps import ApiError
        if not license.allows(feature):
            raise ApiError(404, MISSING.format(label=label))
        if write and not license.allows(feature, write=True):
            raise ApiError(402, EXPIRED.format(label=label))

    return check
