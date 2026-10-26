#!/usr/bin/env python3
"""Helper for dnsone-upgrade-1.5.

    upgrade-1.5-helper.py dnsdist OLD_TEMPLATE NEW_TEMPLATE CURRENT  -> the 1.5 dnsdist.conf on stdout
    upgrade-1.5-helper.py recursor RECURSOR_CONF                     -> recursor.conf with the 1.5 include-dir on stdout

dnsdist: the server's own values (listen addresses, listeners, encrypted DNS, keys, control addresses)
are the only lines an operator sets in dnsdist.conf. They are read from the running file and put into
the 1.5 template. The running file must otherwise be exactly the 1.4 template: if it has other local
edits, nothing is guessed: the differences are printed and the helper fails (merge them by hand).

recursor: recursor.conf holds the server's own API key and sizing, so it is not replaced: the
include-dir line DNSOne's resolver settings need is added after forward-zones-file (already there:
unchanged).
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
        diff = "".join(difflib.unified_diff(expected.splitlines(True), now.splitlines(True), "1.4 template with this server's values", current))
        print(diff, file=sys.stderr)
        fail(f"{current} has local edits besides the server's values (above). Merge them into deploy/dnsdist/dnsdist.conf "
             "of the 1.5 release by hand, install it, and run the upgrade with --keep-dnsdist.")
    return render(new, settings)


INCLUDE = """
# Settings → DNS server → Resolver (EDNS Client Subnet, serve-stale), written by DNSOne as dnsone.conf
# here; DNSOne restarts the Recursor when they change. Settings in that file win over this one.
include-dir=/var/lib/dnsone/recursor/conf.d
"""


def recursor(path: str) -> str:
    text = open(path, encoding="utf-8").read()
    if re.search(r"^include-dir=/var/lib/dnsone/recursor/conf\.d\s*$", text, re.M):
        return text
    if re.search(r"^include-dir=", text, re.M):
        fail(f"{path} already has another include-dir; add /var/lib/dnsone/recursor/conf.d's dnsone.conf to it by hand")
    anchor = re.search(r"^forward-zones-file=.*\n", text, re.M)
    if not anchor:
        return text.rstrip("\n") + "\n" + INCLUDE
    return text[: anchor.end()] + INCLUDE + text[anchor.end() :]


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "dnsdist":
        sys.stdout.write(dnsdist(*sys.argv[2:]))
    elif len(sys.argv) == 3 and sys.argv[1] == "recursor":
        sys.stdout.write(recursor(sys.argv[2]))
    else:
        fail(__doc__)
