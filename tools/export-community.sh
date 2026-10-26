#!/bin/bash
# Builds the DNSOne Community source tree from this repository (DNSOne Pro):
#
#     tools/export-community.sh /path/to/dnsone-community
#
# Community is the same code without the Pro modules (backend/dnsone/edition.py lists them), their console
# screens (frontend/src/pro/), their system files, their tests' subjects and the "(Pro)" parts of the docs.
# The target's own files (.git, LICENSE, README.md, .github) are kept; everything else is replaced.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DST="${1:?usage: tools/export-community.sh TARGET_DIR}"
mkdir -p "$DST"
DST="$(cd "$DST" && pwd)"
[ "$DST" != "$HERE" ] || { echo "the target must not be this repository" >&2; exit 1; }

# Left out of Community.
PRO=(
    backend/dnsone/protection.py backend/dnsone/firewall.py backend/dnsone/transfers.py backend/dnsone/quota.py
    backend/dnsone/legal.py backend/dnsone/oidc.py backend/dnsone/logexport.py
    backend/dnsone/api/protection.py backend/dnsone/api/firewall.py backend/dnsone/api/transfers.py
    backend/dnsone/api/legal.py backend/dnsone/api/cluster.py
    frontend/src/pro/
    ops/dnsone-firewall ops/dnsone-remove-keycloak
    ops/dnsone-upgrade-1.1 ops/dnsone-upgrade-1.2 ops/dnsone-upgrade-1.4 ops/dnsone-upgrade-1.5
    ops/upgrade-1.1-helper.py ops/upgrade-1.4-helper.py ops/upgrade-1.5-helper.py
    deploy/systemd/dnsone-firewall.path deploy/systemd/dnsone-firewall.service deploy/systemd/dnsone-firewall-apply.service
    deploy/nginx/dnsone-legal.conf
    docs/releases/ tools/export-community.sh
)
exclude=(--exclude=.git --exclude=.claude --exclude=node_modules --exclude=.venv --exclude=__pycache__
         --exclude=/frontend/dist --exclude=/LICENSE --exclude=/README.md --exclude=*.egg-info)
for p in "${PRO[@]}"; do exclude+=("--exclude=/$p"); done
rsync -a --delete "${exclude[@]}" "$HERE/" "$DST/"

# The updater installs Community releases from the Community repository.
sed -i 's#^REPO="Pingomni/dnsone"$#REPO="Pingomni/dnsone-community"#' "$DST/ops/dnsone-update"
grep -q '^REPO="Pingomni/dnsone-community"$' "$DST/ops/dnsone-update" || { echo "ops/dnsone-update: REPO line not found" >&2; exit 1; }
sed -i 's#https://github.com/Pingomni/dnsone/blob/main/docs/#https://github.com/Pingomni/dnsone-community/blob/main/docs/#' "$DST/frontend/src/pages/Help.tsx"

# The docs without their "(Pro)" parts, sections renumbered.
python3 "$HERE/tools/community_docs.py" "$DST/docs/USER-GUIDE.md" "$DST/docs/RUNBOOK.md"

# Nothing of Pro may be left behind.
leftover=$(cd "$DST" && grep -rlE "from \.+(api\.)?(protection|firewall|transfers|quota|legal|oidc|logexport) import|import (protection|firewall|transfers|quota|legal|oidc|logexport)$" \
    --include=*.py backend/dnsone || true)
[ -z "$leftover" ] || { echo "still importing a Pro module directly: $leftover" >&2; exit 1; }
echo "DNSOne Community $(cat "$DST/VERSION") written to $DST"
