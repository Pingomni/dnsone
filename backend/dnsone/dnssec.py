"""DNSSEC status of a hosted zone, for the operator who has to give the DS records to the registrar.

BIND signs the zones (see zonegen); DNSOne only reads what BIND serves: the DNSKEY set from the local
BIND, the DS set the parent zone publishes (through the system resolver), and `rndc dnssec -status`.
"""

from __future__ import annotations

import dns.dnssec
import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from .config import Settings, get_settings
from .system import run

SEP = 0x0001  # DNSKEY flag: secure entry point (the key the parent's DS points to)


def _query_bind(s: Settings, name: str, rdtype) -> list:
    query = dns.message.make_query(f"{name}.", rdtype, want_dnssec=True)
    query.flags &= ~0x0100
    try:
        response = dns.query.udp(query, s.bind_address, port=s.bind_port, timeout=2)
        if response.flags & 0x0200:  # truncated: DNSKEY sets with signatures can exceed UDP
            response = dns.query.tcp(query, s.bind_address, port=s.bind_port, timeout=3)
    except (dns.exception.DNSException, OSError):
        return []
    return [rd for rrset in response.answer if rrset.rdtype == rdtype for rd in rrset]


def parent_ds(name: str) -> list[str] | None:
    """The DS records the public DNS has for the zone (None: could not ask)."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    try:
        return sorted(rd.to_text().lower() for rd in resolver.resolve(f"{name}.", "DS", raise_on_no_answer=False) or [])
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except (dns.exception.DNSException, OSError):
        return None


def describe(name: str, state: str, settings: Settings | None = None) -> dict:
    s = settings or get_settings()
    keys = _query_bind(s, name, dns.rdatatype.DNSKEY) if state != "off" else []
    origin = dns.name.from_text(f"{name}.")
    entry = [k for k in keys if k.flags & SEP]
    ds = [dns.dnssec.make_ds(origin, k, "SHA256").to_text().lower() for k in entry]
    parent = parent_ds(name) if state != "off" else None
    status = ""
    if state != "off":
        code, out = run([s.rndc, "-k", str(s.rndc_key), "-s", s.rndc_server, "-p", str(s.rndc_port), "dnssec", "-status", name], timeout=10)
        status = out.strip() if code == 0 else f"rndc dnssec -status failed: {out.strip()[:500]}"
    if state == "off":
        summary = "not signed"
    elif state == "insecure":
        summary = "signing is being removed: delete the DS records at the registrar" if parent else "signing removed"
    elif not keys:
        summary = "signing: BIND is creating the keys (this takes a few seconds after the publish)"
    elif parent is None:
        summary = "signed; the parent's DS records could not be checked"
    elif set(ds) & set(parent):
        summary = "signed and secure: the parent publishes a matching DS record"
    elif parent:
        summary = "signed, but the DS records at the parent do not match these keys: update them at the registrar"
    else:
        summary = "signed; give the DS record below to the registrar to make the zone secure"
    return {
        "summary": summary,
        "keys": [{"tag": dns.dnssec.key_id(k), "flags": k.flags, "algorithm": dns.dnssec.algorithm_to_text(k.algorithm),
                  "dnskey": k.to_text()} for k in keys],
        "ds": ds,
        "parent_ds": parent,
        "secure": bool(parent) and bool(set(ds) & set(parent or [])),
        "bind_status": status,
    }
