"""DNSOne: authoritative zones, caching recursion and RPZ ad-blocking on BIND, PowerDNS Recursor and dnsdist."""

from pathlib import Path

_version_file = Path(__file__).resolve().parents[2] / "VERSION"
__version__ = _version_file.read_text().strip() if _version_file.exists() else "0.0.0"
