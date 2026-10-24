#!/usr/bin/env python3
"""Helper for dnsone-upgrade-1.4.

    upgrade-1.4-helper.py dnsdist OLD_TEMPLATE NEW_TEMPLATE CURRENT  -> the 1.4 dnsdist.conf on stdout
    upgrade-1.4-helper.py nginx SITE_CONF                            -> the nginx site with the 1.4 locations on stdout

dnsdist: the server's own values (listen addresses, listeners, encrypted DNS, keys, control addresses)
are the only lines an operator sets in dnsdist.conf. They are read from the running file and put into
the 1.4 template. The running file must otherwise be exactly the 1.3 template: if it has other local
edits, nothing is guessed: the differences are printed and the helper fails (merge them by hand).
"""

from __future__ import annotations

import difflib
import re
import sys

SETTING = re.compile(
    r"^(local (LISTEN_ADDRESSES|LISTENERS_PER_ADDRESS|ENCRYPTED_DNS|TLS_CERT|TLS_KEY|DOT_PORT|DOH_PORT|DOH_PATHS) = "
    r"|\s+apiKey = |\s+password = |setKey\(|webserver\(\"|controlSocket\(\")"
)


def fail(message: str) -> None:
    print(f"upgrade helper: {message}", file=sys.stderr)
    sys.exit(1)


def _key(line: str) -> str | None:
    m = SETTING.match(line)
    return m.group(1).strip() if m else None


def values(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key = _key(line)
        if key:
            if key in out:
                fail(f"dnsdist.conf sets {key!r} twice")
            out[key] = line
    return out


def render(template: str, settings: dict[str, str]) -> str:
    lines = []
    for line in template.splitlines(keepends=True):
        key = _key(line)
        if key and key in settings:
            lines.append(settings[key] + ("\n" if line.endswith("\n") else ""))
        else:
            lines.append(line)
    return "".join(lines)


def dnsdist(old_template: str, new_template: str, current: str) -> str:
    old, new, now = (open(p, encoding="utf-8").read() for p in (old_template, new_template, current))
    settings = values(now)
    missing = set(values(old)) - set(settings)
    if missing:
        fail(f"{current}: cannot find {', '.join(sorted(missing))}")
    if any("CHANGE_ME" in v for v in settings.values()):
        fail(f"{current}: a value still has its CHANGE_ME placeholder")
    expected = render(old, settings)
    if expected != now:
        diff = "".join(difflib.unified_diff(expected.splitlines(True), now.splitlines(True), "1.3 template with this server's values", current))
        print(diff, file=sys.stderr)
        fail(f"{current} has local edits besides the server's values (above). Merge them into deploy/dnsdist/dnsdist.conf "
             "of the 1.4 release by hand, install it, and run the upgrade with --keep-dnsdist.")
    return render(new, settings)


NGINX_BLOCK = """
    # Single sign-on: rate-limited like the password sign-in.
    location = /api/auth/oidc/login {
        limit_req zone=dnsone_login burst=10 nodelay;
        limit_req_status 429;
        include /etc/nginx/snippets/dnsone-proxy.conf;
    }

    # Dynamic DNS for routers (dyndns2): https://CONSOLE/nic/update?hostname=...&myip=...
    location = /nic/update {
        limit_req zone=dnsone_login burst=20 nodelay;
        limit_req_status 429;
        rewrite ^ /api/ddns/nic/update break;
        include /etc/nginx/snippets/dnsone-proxy.conf;
    }
"""


def nginx(path: str) -> str:
    text = open(path, encoding="utf-8").read()
    if "location = /nic/update" in text:
        return text
    anchor = re.search(r"^    location /api/ \{\n        include /etc/nginx/snippets/dnsone-proxy\.conf;\n    \}\n", text, re.M)
    if not anchor:
        fail(f"{path}: no 'location /api/' block as DNSOne installs it; add the /nic/update and /api/auth/oidc/login locations of deploy/nginx/dnsone.conf by hand")
    return text[: anchor.end()] + NGINX_BLOCK + text[anchor.end() :]


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "dnsdist":
        sys.stdout.write(dnsdist(*sys.argv[2:]))
    elif len(sys.argv) == 3 and sys.argv[1] == "nginx":
        sys.stdout.write(nginx(sys.argv[2]))
    else:
        fail(__doc__)
