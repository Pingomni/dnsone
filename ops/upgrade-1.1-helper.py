#!/usr/bin/env python3
"""Helper for dnsone-upgrade-1.1: reads the 1.0 configuration and patches files in place.

    upgrade-1.1-helper.py read-dnsdist OLD_DNSDIST_CONF          -> JSON of the values to carry over
    upgrade-1.1-helper.py render-dnsdist NEW_TEMPLATE VALUES.json -> the 1.1 dnsdist.conf on stdout
    upgrade-1.1-helper.py patch-recursor RECURSOR_CONF           -> recursor.conf for 1.1 on stdout
    upgrade-1.1-helper.py patch-nginx SITE_CONF                  -> the nginx site for 1.1 on stdout
    upgrade-1.1-helper.py write-backup-cnf DNSONE_ENV BACKUP_CNF -> mysqldump credentials from DNSONE_DATABASE_URL (0600)

Every command fails (exit 1, message on stderr) rather than guess when the input is not what 1.0 wrote.
"""

from __future__ import annotations

import json
import re
import sys


def fail(message: str) -> None:
    print(f"upgrade helper: {message}", file=sys.stderr)
    sys.exit(1)


def _strings(block: str) -> list[str]:
    # Lua list entries, ignoring commented-out lines.
    lines = [ln.split("--", 1)[0] for ln in block.splitlines()]
    return re.findall(r'"([^"]+)"', "\n".join(lines))


def read_dnsdist(path: str) -> dict:
    text = open(path, encoding="utf-8").read()

    def one(pattern: str, what: str) -> re.Match:
        m = re.search(pattern, text, re.M | re.S)
        if not m:
            fail(f"{path}: cannot find {what}")
        return m

    values = {
        "listen_addresses": _strings(one(r"^local LISTEN_ADDRESSES = \{(.*?)\}", "LISTEN_ADDRESSES").group(1)),
        "listeners_per_address": int(one(r"^local LISTENERS_PER_ADDRESS = (\d+)", "LISTENERS_PER_ADDRESS").group(1)),
        "nat_addresses": _strings(one(r"^local NAT_ADDRESSES = \{(.*?)\n\}", "NAT_ADDRESSES").group(1)),
        "public_authoritative": one(r"^local PUBLIC_AUTHORITATIVE = (true|false)", "PUBLIC_AUTHORITATIVE").group(1) == "true",
        "api_key": one(r'apiKey = "([^"]*)"', "the webserver apiKey").group(1),
        "web_password": one(r'password = "([^"]*)"', "the webserver password").group(1),
        "console_key": one(r'^setKey\("([^"]*)"\)', "setKey").group(1),
    }
    qps = one(r"^local CLIENT_QPS, CLIENT_BURST = (\d+), (\d+)", "CLIENT_QPS")
    nat = one(r"^local NAT_QPS, NAT_BURST = (\d+), (\d+)", "NAT_QPS")
    values.update(client_qps=int(qps.group(1)), client_burst=int(qps.group(2)), nat_qps=int(nat.group(1)), nat_burst=int(nat.group(2)))
    if not values["listen_addresses"] or any("CHANGE_ME" in v for v in values["listen_addresses"]):
        fail(f"{path}: LISTEN_ADDRESSES is not set")
    for key in ("api_key", "web_password", "console_key"):
        if not values[key] or "CHANGE_ME" in values[key]:
            fail(f"{path}: {key} still has its placeholder")
    return values


def render_dnsdist(template_path: str, values_path: str) -> str:
    text = open(template_path, encoding="utf-8").read()
    v = json.load(open(values_path, encoding="utf-8"))
    listen = ", ".join(json.dumps(a) for a in v["listen_addresses"])
    replacements = [
        ('local LISTEN_ADDRESSES = { "CHANGE_ME_SERVER_IP" }', f"local LISTEN_ADDRESSES = {{ {listen} }}"),
        ("local LISTENERS_PER_ADDRESS = 4", f"local LISTENERS_PER_ADDRESS = {v['listeners_per_address']}"),
        ('apiKey = "CHANGE_ME_DNSDIST_API_KEY"', f'apiKey = "{v["api_key"]}"'),
        ('password = "CHANGE_ME_DNSDIST_WEB_PASSWORD"', f'password = "{v["web_password"]}"'),
        ('setKey("CHANGE_ME_DNSDIST_CONSOLE_KEY")', f'setKey("{v["console_key"]}")'),
    ]
    for old, new in replacements:
        if text.count(old) != 1:
            fail(f"{template_path}: expected one {old!r}")
        text = text.replace(old, new)
    if re.search(r'"CHANGE_ME_[A-Z_]+"', text):
        fail(f"{template_path}: a placeholder is left")
    return text


def patch_recursor(path: str) -> str:
    text = open(path, encoding="utf-8").read()
    if "lua-dns-script=" in text:
        fail(f"{path}: already has lua-dns-script (upgraded already?)")
    new, count = re.subn(r"^allow-from-file=.*$", "allow-from-file=/var/lib/dnsone/recursor/allow-from.conf", text, flags=re.M)
    if count != 1:
        fail(f"{path}: expected one allow-from-file line")
    new, count = re.subn(r"^(lua-config-file=.*)$",
                         r"\1\n# Per-client groups, paused blocking and regex rules (DNSOne policy script; data in /var/lib/dnsone/recursor).\n"
                         r"lua-dns-script=/etc/powerdns/dnsone.lua", new, flags=re.M)
    if count != 1:
        fail(f"{path}: expected one lua-config-file line")
    return new


NGINX_BLOCKS = """    # Second sign-in step (two-factor codes): rate-limited like the password.
    location = /api/auth/login/verify {
        limit_req zone=dnsone_login burst=10 nodelay;
        limit_req_status 429;
        include /etc/nginx/snippets/dnsone-proxy.conf;
    }

    # Settings → Backup: a restore uploads the whole backup (zones included).
    location = /api/settings/restore {
        client_max_body_size 64m;
        include /etc/nginx/snippets/dnsone-proxy.conf;
    }

"""


def patch_nginx(path: str) -> str:
    text = open(path, encoding="utf-8").read()
    if "/api/auth/login/verify" in text:
        fail(f"{path}: already has the 1.1 locations")
    marker = "    location /api/ {"
    if text.count(marker) != 1:
        fail(f"{path}: expected one '{marker.strip()}'")
    return text.replace(marker, NGINX_BLOCKS + marker)


def write_backup_cnf(env_path: str, out_path: str) -> None:
    import os
    from urllib.parse import unquote, urlsplit
    url = None
    for line in open(env_path, encoding="utf-8"):
        if line.startswith("DNSONE_DATABASE_URL="):
            url = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not url:
        fail(f"{env_path}: no DNSONE_DATABASE_URL")
    u = urlsplit(url.replace("mysql+pymysql://", "mysql://", 1))
    if not u.username or u.password is None or not u.hostname:
        fail(f"{env_path}: DNSONE_DATABASE_URL has no user, password or host")
    body = f"[client]\nuser={unquote(u.username)}\npassword={unquote(u.password)}\nhost={u.hostname}\nport={u.port or 3306}\n"
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(body)


def main() -> None:
    if len(sys.argv) < 3:
        fail(__doc__)
    command, args = sys.argv[1], sys.argv[2:]
    if command == "read-dnsdist":
        print(json.dumps(read_dnsdist(args[0]), indent=2))
    elif command == "render-dnsdist":
        sys.stdout.write(render_dnsdist(args[0], args[1]))
    elif command == "patch-recursor":
        sys.stdout.write(patch_recursor(args[0]))
    elif command == "patch-nginx":
        sys.stdout.write(patch_nginx(args[0]))
    elif command == "write-backup-cnf":
        write_backup_cnf(args[0], args[1])
    else:
        fail(f"unknown command {command}")


if __name__ == "__main__":
    main()
