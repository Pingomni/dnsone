#!/bin/bash
# DNSOne firewall (ufw). Run as root once; review the CHANGE_ME values first.
#   DNS (53/udp, 53/tcp) is open to everyone: dnsdist's ACL decides who may recurse, and the
#   public only gets answers for hosted zones. The console (443) and SSH are limited to the
#   management network. Everything else (MySQL, BIND 5301, Recursor 5300, APIs) stays on loopback.
set -euo pipefail
MGMT_NET="${MGMT_NET:-CHANGE_ME_MGMT_NETWORK}"   # e.g. 10.10.0.0/24
# Encrypted DNS (ENCRYPTED_DNS in dnsdist.conf): the client-facing address(es) DoH listens on,
# space-separated, e.g. ENCRYPTED_DNS_IPS="203.0.113.53". Empty: DoT and DoH stay closed.
ENCRYPTED_DNS_IPS="${ENCRYPTED_DNS_IPS:-}"
case "$MGMT_NET" in CHANGE_ME*) echo "Set MGMT_NET, e.g. MGMT_NET=10.10.0.0/24 $0" >&2; exit 1;; esac

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from "$MGMT_NET" to any port 22 proto tcp comment 'SSH (management)'
ufw allow 53/udp comment 'DNS'
ufw allow 53/tcp comment 'DNS'
ufw allow from "$MGMT_NET" to any port 443 proto tcp comment 'DNSOne console'
ufw allow from "$MGMT_NET" to any port 80 proto tcp comment 'DNSOne console (redirect to HTTPS)'
if [ -n "$ENCRYPTED_DNS_IPS" ]; then
    ufw allow 853/tcp comment 'DNS over TLS'
    for ip in $ENCRYPTED_DNS_IPS; do
        ufw allow proto tcp to "$ip" port 443 comment 'DNS over HTTPS'
    done
fi
# Phase 2: zone transfers to secondaries, e.g.
# ufw allow from 10.0.0.12 to any port 5301 proto tcp comment 'AXFR to ns2'
ufw --force enable
ufw status verbose
