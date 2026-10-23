#!/bin/bash
# Copies RadiusOne's shared UI (styles, components, helpers) into src/, unchanged.
# DNSOne's pages and layout are built on these; run this after a RadiusOne UI update, then `npm run build`.
# RADIUSONE_DIR defaults to the RadiusOne checkout on this server.
set -euo pipefail
SRC="${RADIUSONE_DIR:-/opt/freeradius-web-laravel}/resources"
DST="$(cd "$(dirname "$0")/.." && pwd)/src"
[ -f "$SRC/css/app.css" ] || { echo "RadiusOne not found at $SRC (set RADIUSONE_DIR)" >&2; exit 1; }
mkdir -p "$DST/components" "$DST/lib"
cp "$SRC/css/app.css" "$DST/app.css"
for f in ui table confirm tabs Icon metrics LivePanel settings; do cp "$SRC/js/components/$f.tsx" "$DST/components/$f.tsx"; done
for f in format clock types auth; do cp "$SRC/js/lib/$f.ts" "$DST/lib/$f.ts"; done
echo "Copied RadiusOne UI from $SRC"
