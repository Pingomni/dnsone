"""Shared by the end-to-end tests: the test stack's environment and DNS helpers."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

ENV = os.environ.get("DNSONE_TEST_ENV")

PASSWORD = "integration-password-1"


def _load_env() -> None:
    for line in Path(ENV).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            os.environ[key.strip()] = value.strip().strip('"')
    base, _, _ = os.environ["DNSONE_DATABASE_URL"].rpartition("/")
    os.environ["DNSONE_DATABASE_URL"] = f"{base}/{os.environ.get('DNSONE_TEST_DATABASE', 'dnsone_test')}?charset=utf8mb4"


def dig(name: str, rtype: str, port_env: str = "DNSONE_TEST_DNSDIST", source: str | None = None):
    import dns.flags
    import dns.message
    import dns.query
    import dns.rdatatype

    target = os.environ.get(port_env)
    if not target:
        pytest.skip(f"{port_env} not set")
    host, _, port = target.rpartition(":")
    query = dns.message.make_query(name, getattr(dns.rdatatype, rtype))
    # Ask for validation like dig and validating stubs do: hosted zones must still resolve (NTAs).
    query.flags |= dns.flags.AD
    # source: pose as another customer (any 127.0.0.0/8 address works on loopback).
    return dns.query.udp(query, host, port=int(port), timeout=5, source=source)


def bind_serial(zone: str):
    from dnsone.zonegen import Publisher
    return Publisher().bind_serial(zone)




def eventually(check, timeout: float = 10.0, interval: float = 0.25):
    """Polls check() until it returns something truthy (dnsdist applies settings within 2 s)."""
    import time
    deadline = time.monotonic() + timeout
    while True:
        result = check()
        if result or time.monotonic() > deadline:
            return result
        time.sleep(interval)


def local_address() -> str:
    """A non-loopback address of this machine: a source that is not a customer."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))
        return s.getsockname()[0]


# --------------------------------------------------------------------------- editions

def has(module: str) -> bool:
    """Is the Pro module dnsone.<module> in this edition (DNSOne Community leaves them out)?"""
    # By file, without importing: dnsone.api builds the app when imported.
    from pathlib import Path
    import dnsone
    return (Path(dnsone.__file__).parent / f"{module.replace(".", "/")}.py").exists()


def needs(*modules: str):
    """Skips a test of Pro features where this edition does not have them."""
    import pytest
    missing = [m for m in modules if not has(m)]
    return pytest.mark.skipif(bool(missing), reason=f"needs DNSOne Pro ({', '.join(missing)})")
