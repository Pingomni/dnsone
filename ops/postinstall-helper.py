#!/usr/bin/env python3
"""Helper for dnsone-postinstall.

    postinstall-helper.py nginx-headers SITE_CONF   -> the site with the security headers in every location, on stdout
    postinstall-helper.py dnsdist-xfr DNSDIST_CONF  -> dnsdist.conf refusing zone transfers through port 53 (1.4.5), on stdout

The console's nginx site sets its security headers in the server block, and Cache-Control in the
/assets/ and / locations; nginx then drops the server's headers in those locations. This puts
`include /etc/nginx/snippets/dnsone-headers.conf;` into each location of the server that has its own
add_header (and replaces the server's own header lines with the same include). Already done: unchanged.
"""

from __future__ import annotations

import re
import sys

INCLUDE = "include /etc/nginx/snippets/dnsone-headers.conf;"
HEADERS = ("Strict-Transport-Security", "X-Content-Type-Options", "Referrer-Policy", "X-Frame-Options", "Content-Security-Policy")


def fail(message: str) -> None:
    print(f"postinstall helper: {message}", file=sys.stderr)
    sys.exit(1)


ASSETS_OLD = re.compile(r'^(\s*)expires 1y;\n\s*add_header Cache-Control "public, immutable" always;\n', re.M)


def nginx_headers(text: str) -> str:
    # /assets/: one Cache-Control header instead of expires' and add_header's two.
    text = ASSETS_OLD.sub(lambda m: f'{m.group(1)}add_header Cache-Control "public, max-age=31536000, immutable" always;\n', text)
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    depth = 0
    block: list[str] = []          # what each open brace is: "server", "location", "other"
    location_start: int | None = None
    has_add_header = has_include = False
    server_include_done = False
    for line in lines:
        stripped = line.strip()
        opens, closes = stripped.count("{"), stripped.count("}")
        # The server's own security header lines: one include in their place.
        if block == ["server"] and stripped.startswith("add_header ") and stripped.split()[1] in HEADERS:
            if not server_include_done:
                out.append(line[: len(line) - len(line.lstrip())] + INCLUDE + "\n")
                server_include_done = True
            continue
        if block == ["server"] and stripped == INCLUDE:
            server_include_done = True
        if block and block[-1] == "location" and depth == 2:
            if stripped.startswith("add_header "):
                has_add_header = True
            if stripped == INCLUDE:
                has_include = True
        if closes and block and block[-1] == "location" and depth == 2 and location_start is not None:
            if has_add_header and not has_include:
                indent = re.match(r"\s*", out[location_start + 1] if location_start + 1 < len(out) else line).group(0) or "        "
                out.append(indent + INCLUDE + "\n")
            location_start = None
        out.append(line)
        for _ in range(opens):
            kind = "server" if re.match(r"server\b", stripped) and depth == 0 else "location" if re.match(r"location\b", stripped) else "other"
            block.append(kind)
            depth += 1
            if kind == "location" and depth == 2:
                location_start = len(out) - 1
                has_add_header = has_include = False
        for _ in range(closes):
            if block:
                block.pop()
            depth = max(0, depth - 1)
            if depth == 0:
                server_include_done = False
    return "".join(out)


XFR_BLOCK = """    -- Zone transfers (AXFR/IXFR) through port 53 are refused: dnsdist reaches BIND from 127.0.0.1,
    -- which BIND trusts, so passing them on would let anyone copy every hosted zone (fixed in 1.4.5).
    -- Secondaries transfer from BIND on port 5301 directly.
    table.insert(rules, newRuleAction(OrRule({ QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR) }), RCodeAction(DNSRCode.REFUSED)))
"""
XFR_ANCHOR = """    -- Dynamic DNS updates: to dnsone-ddns, which checks the TSIG key (customers only, or from anywhere).
"""


def dnsdist_xfr(text: str) -> str:
    """The 1.4.5 rule refusing AXFR/IXFR, put where the 1.4.5 template has it. Already there (or a 1.5
    file, which has its own transfer rules): unchanged."""
    if "QTypeRule(DNSQType.AXFR)" in text:
        return text
    if text.count(XFR_ANCHOR) != 1:
        fail("dnsdist.conf has no dynamic DNS rule line as DNSOne 1.4 installs it; add the zone transfer rule of deploy/dnsdist/dnsdist.conf by hand")
    return text.replace(XFR_ANCHOR, XFR_BLOCK + XFR_ANCHOR)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "nginx-headers":
        sys.stdout.write(nginx_headers(open(sys.argv[2], encoding="utf-8").read()))
    elif len(sys.argv) == 3 and sys.argv[1] == "dnsdist-xfr":
        sys.stdout.write(dnsdist_xfr(open(sys.argv[2], encoding="utf-8").read()))
    else:
        fail(__doc__)
