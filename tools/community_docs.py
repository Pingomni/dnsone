"""The Community docs from the Pro ones (tools/export-community.sh): drops what is marked "(Pro)".

- a heading with "(Pro)": the section, up to the next heading of the same or a higher level;
- a table row or list item with "(Pro)" (a list item with its indented continuation lines);
- runbook upgrade notes ("#### From 1.x to 1.y"): Community starts at its first release.

Then the guide's numbered "## N." sections are numbered again, its contents list rebuilt, and "section N"
and "#N-…" references follow the new numbers.

    python3 tools/community_docs.py docs/USER-GUIDE.md docs/RUNBOOK.md
"""
import re
import sys
from pathlib import Path

MARK = "(Pro)"
HEADING = re.compile(r"^(#{2,6}) ")


def slug(text: str) -> str:
    return re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", text.lower()).strip())


def strip(lines: list[str]) -> list[str]:
    out: list[str] = []
    skip_level = 0
    i = 0
    fence = False
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            fence = not fence
        m = None if fence else HEADING.match(line)
        if m:
            level = len(m.group(1))
            if skip_level and level <= skip_level:
                skip_level = 0
            if not skip_level and (MARK in line or re.match(r"^#### From \d+\.\d+ to \d+\.\d+", line)):
                skip_level = level
        if skip_level:
            i += 1
            continue
        stripped = line.lstrip()
        if not fence and MARK in line and (stripped.startswith("|") or re.match(r"^(- |\d+\. )", stripped)):
            indent = len(line) - len(stripped)
            i += 1
            # The item's continuation lines (indented further), not the next item.
            while not stripped.startswith("|") and i < len(lines) and lines[i].strip() and len(lines[i]) - len(lines[i].lstrip()) > indent \
                    and not re.match(r"^(- |\d+\. )", lines[i].lstrip()):
                i += 1
            continue
        out.append(line)
        i += 1
    return out


def renumber(lines: list[str]) -> list[str]:
    """## N. sections numbered again, the contents list rebuilt, references to the old numbers updated."""
    numbered = [(i, re.match(r"^## (\d+)\. (.+)$", l)) for i, l in enumerate(lines)]
    numbered = [(i, m) for i, m in numbered if m]
    if not numbered:
        return lines
    old_to_new, anchors = {}, {}
    for new, (i, m) in enumerate(numbered, 1):
        old, title = int(m.group(1)), m.group(2)
        old_to_new[old] = new
        anchors[slug(f"{old}. {title}")] = slug(f"{new}. {title}")
        lines[i] = f"## {new}. {title}"
    text = "\n".join(lines)
    text = re.sub(r"\bsections? (\d+)\b", lambda m: m.group(0).replace(m.group(1), str(old_to_new.get(int(m.group(1)), m.group(1)))), text)
    text = re.sub(r"\(#([\w-]+)\)", lambda m: f"(#{anchors.get(m.group(1), m.group(1))})", text)
    lines = text.split("\n")
    # The contents list: between "## Contents" and the next "---" or heading.
    if "## Contents" in lines:
        start = lines.index("## Contents") + 1
        end = start
        while end < len(lines) and lines[end].strip() != "---" and not HEADING.match(lines[end]):
            end += 1
        contents = [f"{n}. [{m.group(2)}](#{slug(f'{n}. ' + m.group(2))})" for n, (_, m) in enumerate(numbered, 1)]
        lines[start:end] = ["", *contents, ""]
    return lines


# Sentences that mention a Pro feature in passing, in Community words (exact: the export stops if one is missing).
REWORD = {
    "USER-GUIDE.md": [
        ("operators, administrators, resellers and\ncustomers", "operators, administrators and\ncustomers"),
        ("DNSOne runs an ISP's DNS on one server (or a cluster):", "DNSOne runs an ISP's DNS on one server:"),
        ("can block ads, malware and court-ordered names, per group of", "can block ads and malware, per group of"),
        ("| operator | zones, ad-blocking, groups, court orders (read), protection, query log, audit log |",
         "| operator | zones, ad-blocking, groups, query log, audit log |"),
        ("(ok, blocked, allowed by a rule,\n  court order)", "(ok, blocked, allowed by a\n  rule)"),
        ("accounts, roles, the zones of customers and resellers, quotas, resetting two-factor",
         "accounts, roles, the zones of customer accounts, resetting two-factor"),
        ("a certificate, a cluster node, a query flood", "a certificate, a query flood"),
        ("download zones, ad-blocking, settings and court orders as one file", "download zones, ad-blocking and settings as one file"),
        ("does not pause court orders or Safe Search", "does not pause Safe Search"),
    ],
    "RUNBOOK.md": [
        ("Backup and restore; Cluster)", "Backup and restore)"),
        ("[GitHub](https://github.com/Pingomni/dnsone/releases) (on a cluster: every node, the primary first):",
         "[GitHub](https://github.com/Pingomni/dnsone-community/releases):"),
        (" On clusters, secondaries\ntransfer the signed zone; only the primary holds keys.", ""),
    ],
}


def reword(name: str, text: str) -> str:
    for old, new in REWORD.get(Path(name).name, []):
        if text.count(old) != 1:
            sys.exit(f"{name}: the Community wording no longer matches: {old[:60]!r}")
        text = text.replace(old, new)
    return text


for name in sys.argv[1:]:
    path = Path(name)
    lines = path.read_text().split("\n")
    lines = renumber(strip(lines))
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines))
    text = reword(name, text)
    if MARK in text:
        left = [l for l in text.split("\n") if MARK in l]
        sys.exit(f"{name}: still marked {MARK}: {left[:3]}")
    path.write_text(text)
    print(f"{name}: Community docs")
