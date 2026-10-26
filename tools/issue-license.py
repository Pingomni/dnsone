#!/usr/bin/env python3
"""Issues a DNSOne Pro licence key, signed with PingOmni's private key (never stored in this repository).

    tools/issue-license.py --customer "Example ISP" --expires 2027-10-31
    tools/issue-license.py --customer "Example ISP" --expires 2027-10-31 --features protection,firewall
    tools/issue-license.py --show DNSONE1....                      # what a key contains (no key needed)

The customer pastes the printed key under Settings → License. Features: all (the default) or a comma list of
protection, firewall, transfers, quota, legal, oidc, logexport, cluster. Only `cryptography` is needed.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
from datetime import date
from pathlib import Path

from cryptography.hazmat.primitives import serialization

FEATURES = ("protection", "firewall", "transfers", "quota", "legal", "oidc", "logexport", "cluster")
DEFAULT_KEY = Path(os.environ.get("DNSONE_LICENSE_SIGNING_KEY", "~/.config/pingomni/dnsone-license-ed25519.pem")).expanduser()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main() -> int:
    p = argparse.ArgumentParser(description="Issue a DNSOne Pro licence key.")
    p.add_argument("--customer", help="the licensee, as shown in their console")
    p.add_argument("--expires", help="last day of the licence, YYYY-MM-DD")
    p.add_argument("--features", default="all", help="all, or a comma list: " + ", ".join(FEATURES))
    p.add_argument("--key", type=Path, default=DEFAULT_KEY, help=f"the Ed25519 signing key (default {DEFAULT_KEY})")
    p.add_argument("--show", metavar="LICENCE", help="print what a licence key contains, and stop")
    args = p.parse_args()

    if args.show:
        payload = base64.urlsafe_b64decode(args.show.split(".")[1] + "==")
        print(json.dumps(json.loads(payload), indent=2))
        return 0
    if not args.customer or not args.expires:
        p.error("--customer and --expires are needed")
    expires = date.fromisoformat(args.expires)
    features = ["all"] if args.features == "all" else [f.strip() for f in args.features.split(",") if f.strip()]
    unknown = [f for f in features if f != "all" and f not in FEATURES]
    if unknown:
        p.error(f"unknown feature(s): {', '.join(unknown)}")

    private = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
    payload = json.dumps({"v": 1, "id": secrets.token_hex(6), "customer": args.customer.strip(), "issued": date.today().isoformat(),
                          "expires": expires.isoformat(), "features": features}, separators=(",", ":")).encode()
    print(f"DNSONE1.{b64(payload)}.{b64(private.sign(payload))}")
    print(f"# {args.customer}: {', '.join(features)} until {expires} ({(expires - date.today()).days} days)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
