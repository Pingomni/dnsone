#!/usr/bin/env python3
"""Issues a DNSOne Pro licence key, signed with PingOmni's private key (never stored in this repository).

    tools/issue-license.py --customer "Example ISP" --server DNS1-AAAA-BBBB-CCCC-DDDD --expires 2027-10-31
    tools/issue-license.py --customer "Example ISP" --server DNS1-AAAA-BBBB-CCCC-DDDD --servers 2 --expires 2027-10-31
    tools/issue-license.py --show DNSONE1....                      # what a key contains (no key needed)

--server is the server ID the customer reads under Settings → License (for a cluster: any one of its servers,
usually the primary); --servers is how many servers the key covers (a cluster: all of them). The customer
pastes the printed key under Settings → License, on one server; a cluster's servers share it.
Features: all (the default) or a comma list of protection, firewall, transfers, quota, legal, oidc,
logexport, cluster. Only `cryptography` is needed.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
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
    p.add_argument("--server", help="the server ID from Settings → License (DNS1-XXXX-XXXX-XXXX-XXXX)")
    p.add_argument("--servers", type=int, default=1, help="how many servers the key covers (default 1; a cluster: all of them)")
    p.add_argument("--features", default="all", help="all, or a comma list: " + ", ".join(FEATURES))
    p.add_argument("--key", type=Path, default=DEFAULT_KEY, help=f"the Ed25519 signing key (default {DEFAULT_KEY})")
    p.add_argument("--show", metavar="LICENCE", help="print what a licence key contains, and stop")
    args = p.parse_args()

    if args.show:
        payload = base64.urlsafe_b64decode(args.show.split(".")[1] + "==")
        print(json.dumps(json.loads(payload), indent=2))
        return 0
    if not args.customer or not args.expires or not args.server:
        p.error("--customer, --server and --expires are needed")
    server = args.server.strip().upper()
    if not re.fullmatch(r"DNS1(?:-[A-Z2-7]{4}){4}", server):
        p.error("--server: copy the server ID from Settings → License (DNS1-XXXX-XXXX-XXXX-XXXX)")
    if args.servers < 1:
        p.error("--servers: 1 or more")
    expires = date.fromisoformat(args.expires)
    features = ["all"] if args.features == "all" else [f.strip() for f in args.features.split(",") if f.strip()]
    unknown = [f for f in features if f != "all" and f not in FEATURES]
    if unknown:
        p.error(f"unknown feature(s): {', '.join(unknown)}")

    private = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
    payload = json.dumps({"v": 1, "product": "dnsone", "id": secrets.token_hex(6), "customer": args.customer.strip(), "issued": date.today().isoformat(),
                          "expires": expires.isoformat(), "features": features, "server": server,
                          "servers": args.servers}, separators=(",", ":")).encode()
    print(f"DNSONE1.{b64(payload)}.{b64(private.sign(payload))}")
    print(f"# {args.customer}: {', '.join(features)}, {args.servers} server(s) with {server}, until {expires} "
          f"({(expires - date.today()).days} days)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
