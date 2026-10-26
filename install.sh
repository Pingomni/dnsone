#!/bin/bash
# DNSOne installer: sets up DNSOne on a fresh Ubuntu 24.04 LTS server with one command. Run as root:
#
#     curl -fsSL https://raw.githubusercontent.com/Pingomni/dnsone/main/install.sh -o install.sh
#     sudo bash install.sh
#
# It asks for four values (each with a suggestion from this server; Enter keeps it), then does every step
# of docs/RUNBOOK.md (steps 0 to 2, and the backups of step 7) by itself:
#   1. installs BIND, the PowerDNS Recursor, dnsdist, MySQL 8 and nginx from Ubuntu
#   2. downloads the latest DNSOne release from GitHub (the console already built, no Node.js needed),
#      checks its checksum and installs it in /opt/dnsone
#   3. generates every secret into /root/dnsone-secrets.env (0600), creates the database and the first
#      administrator (with a generated password, shown at the end)
#   4. configures BIND, the Recursor, dnsdist, nginx (HTTPS, self-signed until you add your certificate),
#      the systemd units, timers, log rotation and daily backups
#   5. checks that every service runs and the console answers
#
# Options (all optional; without --yes it asks for the values it was not given):
#     --server-ip IP          the address clients send DNS to (dnsdist, port 53)
#     --mgmt-ip IP            the address the console listens on (nginx, 443); default: the server IP
#     --mgmt-net CIDR         who may reach SSH and the console (used by --ufw and shown in the summary)
#     --fqdn NAME             the console's host name (for the TLS certificate)
#     --client-networks LIST  customer networks allowed to use the resolver, comma-separated (added to the
#                             private ranges 10/8, 172.16/12, 192.168/16 and 100.64/10)
#     --admin NAME            the first administrator's user name (default: admin)
#     --admin-email EMAIL     its email address
#     --timezone ZONE         the timezone the console shows times in (default: this server's)
#     --version vX.Y.Z        a given release instead of the latest
#     --source DIR            install from a built source tree (with frontend/dist) instead of downloading
#     --ufw                   also turn on ufw: DNS open, SSH and the console from --mgmt-net only.
#                             Without it, turn on DNSOne's own firewall in the console (Settings -> Firewall).
#     --yes                   no questions: use the values given and the suggestions for the rest
#
# Safe to run again: if a step fails, fix the cause and run it again; it keeps the secrets, the database
# and the files it already made. On a server where DNSOne is installed it stops: use `sudo dnsone-update`.
set -euo pipefail
umask 022

REPO="Pingomni/dnsone"
SECRETS=/root/dnsone-secrets.env
MARKER=/var/lib/dnsone/installed
REL=/opt/dnsone

log() { printf '\n== %s\n' "$*"; }
fail() { printf '\nINSTALL STOPPED: %s\n' "$*" >&2; exit 1; }

server_ip="" mgmt_ip="" mgmt_net="" fqdn="" client_nets="" admin="admin" admin_email="" timezone=""
want="" source_dir="" use_ufw=0 yes=0
while [ $# -gt 0 ]; do
    case "$1" in
        --server-ip) server_ip="${2:?}"; shift ;;
        --mgmt-ip) mgmt_ip="${2:?}"; shift ;;
        --mgmt-net) mgmt_net="${2:?}"; shift ;;
        --fqdn) fqdn="${2:?}"; shift ;;
        --client-networks) client_nets="${2:?}"; shift ;;
        --admin) admin="${2:?}"; shift ;;
        --admin-email) admin_email="${2:?}"; shift ;;
        --timezone) timezone="${2:?}"; shift ;;
        --version) want="${2:?}"; shift ;;
        --source) source_dir="${2:?}"; shift ;;
        --ufw) use_ufw=1 ;;
        --yes|-y) yes=1 ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) fail "unknown option $1 (see: bash $0 --help)" ;;
    esac
    shift
done

# ---------------------------------------------------------------------------------------------------
log "Checks"
[ "$(id -u)" = 0 ] || fail "run as root (sudo bash $0)"
. /etc/os-release
[ "${ID:-}" = ubuntu ] && [ "${VERSION_ID:-}" = 24.04 ] || fail "DNSOne needs Ubuntu 24.04 LTS (this is ${PRETTY_NAME:-unknown})"
[ "$(uname -m)" = x86_64 ] || [ "$(uname -m)" = aarch64 ] || fail "unsupported architecture $(uname -m)"
if [ -f "$MARKER" ]; then
    fail "DNSOne $(cat $REL/VERSION 2>/dev/null) is already installed here. Update it with: sudo dnsone-update"
fi
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
[ "$mem_mb" -ge 1800 ] || fail "DNSOne needs at least 2 GB of RAM (this server has ${mem_mb} MB)"
disk_mb=$(df -Pm / | awk 'NR==2 {print $4}')
[ "$disk_mb" -ge 4000 ] || fail "DNSOne needs at least 4 GB free on / (${disk_mb} MB free)"
resume=0
[ -f "$SECRETS" ] && resume=1 && echo "Found $SECRETS from an earlier run: continuing with its values."
echo "OK"

# ---------------------------------------------------------------------------------------------------
# Values: from the options, an earlier run, or questions with this server's values as suggestions.
ask() {  # ask VAR "question" "suggestion"
    local var="$1" question="$2" suggestion="$3" answer=""
    if [ -n "${!var}" ]; then return 0; fi
    if [ "$yes" = 1 ] || [ ! -r /dev/tty ]; then
        printf -v "$var" '%s' "$suggestion"
        return 0
    fi
    read -r -p "$question [$suggestion]: " answer < /dev/tty || true
    printf -v "$var" '%s' "${answer:-$suggestion}"
}
is_ip() { python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$1" 2>/dev/null; }
is_net() { python3 -c 'import ipaddress, sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$1" 2>/dev/null; }
local_ip() { ip -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -qxF "$1"; }

if [ "$resume" = 1 ]; then
    # shellcheck disable=SC1090
    . "$SECRETS"
    server_ip="$SERVER_IP" mgmt_ip="$MGMT_IP" mgmt_net="$MGMT_NET" fqdn="$CONSOLE_FQDN"
    admin="${ADMIN_USER:-$admin}" admin_email="${ADMIN_EMAIL:-$admin_email}"
    client_nets="${CLIENT_NETWORKS:-$client_nets}" timezone="${TIMEZONE:-$timezone}"
else
    log "Values for this server (Enter keeps the suggestion)"
    default_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
    ask server_ip "Address clients send DNS to" "$default_ip"
    is_ip "$server_ip" && local_ip "$server_ip" || fail "$server_ip is not an address of this server (ip addr)"
    ask mgmt_ip "Address the web console listens on" "$server_ip"
    is_ip "$mgmt_ip" && local_ip "$mgmt_ip" || fail "$mgmt_ip is not an address of this server (ip addr)"
    default_net="$(ip -o addr show | awk -v ip="$mgmt_ip" '{split($4, a, "/"); if (a[1] == ip) print $4}' | head -1)"
    default_net="$(python3 -c 'import ipaddress, sys; print(ipaddress.ip_network(sys.argv[1], strict=False))' "${default_net:-$mgmt_ip/32}")"
    ask mgmt_net "Management network (who may reach SSH and the console)" "$default_net"
    is_net "$mgmt_net" || fail "$mgmt_net is not a network (e.g. 10.10.0.0/24)"
    ask fqdn "Host name of the console" "$(hostname -f 2>/dev/null || hostname)"
    [[ "$fqdn" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || fail "$fqdn is not a host name"
    ask client_nets "Public customer networks besides the private ranges, comma-separated (empty: none)" ""
    ask timezone "Timezone for the console" "$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
    ask admin_email "Administrator's email" "$admin@$fqdn"
fi
client_nets="${client_nets// /}"
for net in ${client_nets//,/ }; do
    is_net "$net" || fail "customer network $net is not a network (e.g. 203.0.113.0/24)"
done
[ "$use_ufw" = 1 ] && [ -z "$mgmt_net" ] && fail "--ufw needs --mgmt-net"
cat <<EOF

  DNS for clients      $server_ip:53
  Console              https://$fqdn/ on $mgmt_ip:443
  Management network   $mgmt_net
  Customer networks    10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 ${client_nets//,/ }
  Administrator        $admin <$admin_email>
  Firewall             $([ "$use_ufw" = 1 ] && echo "ufw" || echo "none yet: turn it on in the console (Settings -> Firewall)")
EOF
if [ "$yes" = 0 ] && [ "$resume" = 0 ] && [ -r /dev/tty ]; then
    read -r -p "Install DNSOne with these values? [Y/n] " go < /dev/tty || true
    case "${go:-y}" in [Yy]*) ;; *) fail "nothing was changed" ;; esac
fi

# Port 53 on the DNS address must be free for dnsdist (systemd-resolved's 127.0.0.53 does not clash).
busy="$(ss -Hlnup 'sport = :53' 2>/dev/null; ss -Hlntp 'sport = :53' 2>/dev/null)"
busy="$(printf '%s\n' "$busy" | awk -v ip="$server_ip" '$4 == ip":53" || $4 == "0.0.0.0:53" || $4 == "*:53" || $4 == "[::]:53"' \
        | grep -v -e '"dnsdist"' -e '"named"' -e '"pdns_recursor"' || true)"
[ -z "$busy" ] || fail "another program answers on port 53 of $server_ip; stop it first:
$busy"

# ---------------------------------------------------------------------------------------------------
log "1. Packages"
# Keep the new daemons from starting with Ubuntu's defaults (BIND would take port 53); each is started
# below once it has DNSOne's configuration.
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d
trap 'rm -f /usr/sbin/policy-rc.d' EXIT
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q -o Dpkg::Options::=--force-confold \
    bind9 bind9-utils bind9-dnsutils pdns-recursor dnsdist mysql-server-8.0 nginx \
    python3-venv python3-dev build-essential sudo ufw nftables openssl jq curl rsync ca-certificates
rm -f /usr/sbin/policy-rc.d
trap - EXIT
systemctl enable --quiet --now mysql
echo "OK    $(named -v), $(dnsdist --version 2>/dev/null | head -1), $(mysqld --version | awk '{print $1, $3}')"

# ---------------------------------------------------------------------------------------------------
log "2. DNSOne"
if [ -n "$source_dir" ]; then
    src="$(cd "$source_dir" && pwd)"
    [ -f "$src/frontend/dist/index.html" ] || fail "$src has no built console (frontend/dist); build it with npm ci && npm run build"
else
    if [ -n "$want" ]; then
        tag="$want"
    else
        tag="$(curl -fsSL --max-time 20 "https://api.github.com/repos/$REPO/releases/latest" \
               | python3 -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])')" \
            || fail "cannot read the latest release from https://github.com/$REPO/releases"
    fi
    version="${tag#v}"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "release $tag is not a vX.Y.Z version"
    dir=/var/lib/dnsone/updates/$version
    rm -rf "$dir" && mkdir -p "$dir"
    url="https://github.com/$REPO/releases/download/v$version/dnsone-$version.tar.gz"
    echo "Downloading $url"
    curl -fsSL --max-time 300 -o "$dir/dnsone-$version.tar.gz" "$url" || fail "cannot download $url"
    curl -fsSL --max-time 30 -o "$dir/dnsone-$version.tar.gz.sha256" "$url.sha256" || fail "cannot download $url.sha256"
    (cd "$dir" && sha256sum --quiet -c "dnsone-$version.tar.gz.sha256") || fail "the download does not match its checksum"
    tar -xzf "$dir/dnsone-$version.tar.gz" -C "$dir"
    src="$dir/dnsone-$version"
    [ "$(cat "$src/VERSION")" = "$version" ] || fail "the archive is not DNSOne $version"
    [ -f "$src/frontend/dist/index.html" ] || fail "the archive has no built console"
fi
if [ "$src" != "$REL" ]; then
    mkdir -p "$REL"
    rsync -a --delete --exclude '/backend/.venv' --exclude '/frontend/node_modules' --exclude '__pycache__' \
          --exclude '.pytest_cache' --exclude '*.egg-info' --exclude '.git' "$src/" "$REL/"
fi
chown -R root:root "$REL" && chmod -R go-w "$REL"
echo "OK    DNSOne $(cat $REL/VERSION) in $REL"

# ---------------------------------------------------------------------------------------------------
log "3. Service user, directories and the application"
id dnsone >/dev/null 2>&1 || adduser --system --group --no-create-home --home /nonexistent dnsone
usermod -aG bind dnsone
install -d -o dnsone -g bind   -m 2750 /etc/bind/dnsone
install -d -o dnsone -g bind   -m 2770 /var/lib/bind/zones
install -d -o bind   -g bind   -m 0750 /var/lib/bind/keys
install -d -o dnsone -g dnsone -m 0755 /var/lib/dnsone /var/lib/dnsone/rpz /var/lib/dnsone/recursor \
                                        /var/lib/dnsone/recursor/conf.d /var/lib/dnsone/dnsdist
install -d -o dnsone -g dnsone -m 0750 /var/lib/dnsone/blocklists
install -d -o dnsone -g adm    -m 0750 /var/log/dnsone
install -d -o root   -g dnsone -m 0750 /etc/dnsone
install -d -o root   -g root   -m 0700 /var/backups/dnsone
[ -x "$REL/backend/.venv/bin/python" ] || python3 -m venv "$REL/backend/.venv"
"$REL/backend/.venv/bin/pip" install --quiet --upgrade pip
"$REL/backend/.venv/bin/pip" install --quiet -e "$REL/backend"
install -m 0755 "$REL/ops/dnsone-ctl" /usr/local/sbin/dnsone-ctl
install -m 0755 "$REL/ops/dnsone-status" /usr/local/sbin/dnsone-status
install -m 0755 "$REL/ops/dnsone-update" /usr/local/sbin/dnsone-update
echo "OK"

# ---------------------------------------------------------------------------------------------------
log "4. Secrets, database and the first administrator"
if [ "$resume" = 0 ]; then
    install -m 0600 /dev/null "$SECRETS"
    cat > "$SECRETS" <<EOF
# DNSOne: this server's values and secrets, written by install.sh. Keep this file (root only).
SERVER_IP=$server_ip
MGMT_IP=$mgmt_ip
MGMT_NET=$mgmt_net
CONSOLE_FQDN=$fqdn
CLIENT_NETWORKS=$client_nets
TIMEZONE=$timezone
ADMIN_USER=$admin
ADMIN_EMAIL=$admin_email
ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)
DB_PASS=$(openssl rand -hex 24)
REC_API_KEY=$(openssl rand -hex 24)
DIST_API_KEY=$(openssl rand -hex 24)
DIST_WEB_PASSWORD=$(openssl rand -hex 24)
DIST_CONSOLE_KEY=$(head -c32 /dev/urandom | base64)
EOF
fi
# shellcheck disable=SC1090
. "$SECRETS"

mysql <<SQL
CREATE DATABASE IF NOT EXISTS dnsone CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER IF NOT EXISTS 'dnsone'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
ALTER USER 'dnsone'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON dnsone.* TO 'dnsone'@'127.0.0.1';
SQL
if [ ! -f /etc/dnsone/dnsone.env ]; then
    install -o root -g dnsone -m 0640 "$REL/deploy/env/dnsone.env" /etc/dnsone/dnsone.env
    sed -i -e "s#CHANGE_ME_DB_PASSWORD#${DB_PASS}#" -e "s#CHANGE_ME_RECURSOR_API_KEY#${REC_API_KEY}#" \
           -e "s#CHANGE_ME_DNSDIST_API_KEY#${DIST_API_KEY}#" -e "s#^DNSONE_NODE_NAME=.*#DNSONE_NODE_NAME=$(hostname -s)#" \
           -e "s#^DNSONE_TIMEZONE=.*#DNSONE_TIMEZONE=${TIMEZONE:-UTC}#" \
           /etc/dnsone/dnsone.env
fi
printf '[client]\nuser=dnsone\npassword=%s\nhost=127.0.0.1\n' "$DB_PASS" | install -m 0600 /dev/stdin /etc/dnsone/backup.cnf
dnsone-ctl migrate
if [ "$(mysql -N -e 'SELECT COUNT(*) FROM dnsone.users')" = 0 ]; then
    printf '%s\n' "$ADMIN_PASSWORD" | dnsone-ctl create-admin "$ADMIN_USER" --email "$ADMIN_EMAIL"
fi
echo "OK"

# ---------------------------------------------------------------------------------------------------
log "5. BIND (authoritative, 127.0.0.1:5301)"
install -o root -g bind -m 0644 "$REL/deploy/bind/named.conf.options" /etc/bind/named.conf.options
install -o root -g bind -m 0644 "$REL/deploy/bind/named.conf.local"   /etc/bind/named.conf.local
[ -f /etc/bind/rndc.key ] || rndc-confgen -a
if [ ! -s /etc/bind/dnsone/dnsone-rndc.key ]; then
    tsig-keygen -a hmac-sha256 dnsone-rndc > /etc/bind/dnsone/dnsone-rndc.key
fi
chown root:bind /etc/bind/dnsone/dnsone-rndc.key && chmod 0640 /etc/bind/dnsone/dnsone-rndc.key
[ -f /etc/bind/dnsone/zones.conf ] || install -o dnsone -g bind -m 0640 /dev/null /etc/bind/dnsone/zones.conf
named-checkconf
systemctl enable --quiet named && systemctl restart named
echo "OK"

log "6. PowerDNS Recursor (cache and ad-blocking, 127.0.0.1:5300)"
install -o root -g pdns -m 0640 "$REL/deploy/recursor/recursor.conf" /etc/powerdns/recursor.conf
install -o root -g pdns -m 0644 "$REL/deploy/recursor/recursor.lua"  /etc/powerdns/recursor.lua
install -o root -g pdns -m 0644 "$REL/deploy/recursor/dnsone.lua"    /etc/powerdns/dnsone.lua
sed -i "s#CHANGE_ME_RECURSOR_API_KEY#${REC_API_KEY}#" /etc/powerdns/recursor.conf
# Customer networks until they are set in the console (Settings -> DNS server).
{
    sed '/CHANGE_ME/d' "$REL/deploy/dnsone/client-networks.conf"
    for net in ${CLIENT_NETWORKS//,/ }; do echo "$net"; done
} | install -o root -g root -m 0644 /dev/stdin /etc/dnsone/client-networks.conf
grep -v '^#' /etc/dnsone/client-networks.conf | install -o dnsone -g dnsone -m 0644 /dev/stdin /var/lib/dnsone/recursor/allow-from.conf
for f in recursor/forward-zones.conf recursor/negative-trust-anchors.txt recursor/conf.d/dnsone.conf dnsdist/auth-zones.txt; do
    [ -f "/var/lib/dnsone/$f" ] || install -o dnsone -g dnsone -m 0644 /dev/null "/var/lib/dnsone/$f"
done
if [ ! -f /var/lib/dnsone/rpz/dnsone.rpz ]; then
    printf '$TTL 60\n@ IN SOA localhost. hostmaster.localhost. 1 3600 600 86400 60\n@ IN NS localhost.\n' \
        | install -o dnsone -g dnsone -m 0644 /dev/stdin /var/lib/dnsone/rpz/dnsone.rpz
fi
systemctl enable --quiet pdns-recursor && systemctl restart pdns-recursor
echo "OK"

log "7. dnsdist (port 53 on $SERVER_IP: who may recurse, rate limits)"
install -o root -g _dnsdist -m 0640 "$REL/deploy/dnsdist/dnsdist.conf" /etc/dnsdist/dnsdist.conf
sed -i -e "s#CHANGE_ME_SERVER_IP#${SERVER_IP}#" -e "s#CHANGE_ME_DNSDIST_API_KEY#${DIST_API_KEY}#" \
       -e "s#CHANGE_ME_DNSDIST_WEB_PASSWORD#${DIST_WEB_PASSWORD}#" -e "s#CHANGE_ME_DNSDIST_CONSOLE_KEY#${DIST_CONSOLE_KEY}#" \
       /etc/dnsdist/dnsdist.conf
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf >/dev/null
systemctl enable --quiet dnsdist && systemctl restart dnsdist
echo "OK"

log "8. DNSOne services, timers, sudo rules and log rotation"
visudo -cf "$REL/deploy/sudoers/dnsone" >/dev/null
install -o root -g root -m 0440 "$REL/deploy/sudoers/dnsone" /etc/sudoers.d/dnsone
install -m 0644 "$REL"/deploy/systemd/dnsone-*.service "$REL"/deploy/systemd/dnsone-*.timer /etc/systemd/system/
install -m 0644 "$REL/deploy/logrotate/dnsone" /etc/logrotate.d/dnsone
systemctl daemon-reload
systemctl enable --quiet --now dnsone-api.service dnsone-querylog.service dnsone-ddns.service
systemctl enable --quiet --now dnsone-sync.timer dnsone-reconcile.timer dnsone-rpz.timer dnsone-stats.timer dnsone-backup.timer
dnsone-ctl sync
echo "OK"

log "9. nginx (the console over HTTPS)"
install -d -m 0750 /etc/ssl/dnsone
if [ ! -f /etc/ssl/dnsone/dnsone.crt ]; then
    openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=${CONSOLE_FQDN}" \
        -addext "subjectAltName=DNS:${CONSOLE_FQDN},IP:${MGMT_IP}" \
        -keyout /etc/ssl/dnsone/dnsone.key -out /etc/ssl/dnsone/dnsone.crt 2>/dev/null
    chmod 0600 /etc/ssl/dnsone/dnsone.key
fi
install -m 0644 "$REL/deploy/nginx/dnsone-proxy.conf" /etc/nginx/snippets/dnsone-proxy.conf
install -m 0644 "$REL/deploy/nginx/dnsone-headers.conf" /etc/nginx/snippets/dnsone-headers.conf
install -m 0644 "$REL/deploy/nginx/dnsone.conf" /etc/nginx/sites-available/dnsone
sed -i -e "s#CHANGE_ME_MGMT_IP#${MGMT_IP}#g" -e "s#CHANGE_ME_FQDN#${CONSOLE_FQDN}#g" /etc/nginx/sites-available/dnsone
ln -sf /etc/nginx/sites-available/dnsone /etc/nginx/sites-enabled/dnsone
rm -f /etc/nginx/sites-enabled/default
nginx -t 2>/dev/null || { nginx -t; fail "nginx rejected the console's site"; }
systemctl enable --quiet nginx && systemctl restart nginx
echo "OK"

log "10. Firewall, updates from the console"
# The release's post-install: the firewall units (Settings -> Firewall), installing updates from the
# console (Settings -> Overview), nginx security headers.
bash "$REL/ops/dnsone-postinstall"
if [ "$use_ufw" = 1 ]; then
    MGMT_NET="$MGMT_NET" bash "$REL/deploy/ufw.sh"
fi
echo "OK"

# ---------------------------------------------------------------------------------------------------
log "11. Verification"
problems=0
for unit in mysql named pdns-recursor dnsdist nginx dnsone-api dnsone-querylog dnsone-ddns; do
    if systemctl is-active --quiet "$unit"; then echo "OK    $unit"; else echo "FAIL  $unit is not running (journalctl -u $unit)"; problems=1; fi
done
ok=0
for _ in $(seq 30); do
    curl -fsk --max-time 3 "https://$MGMT_IP/api/health" >/dev/null 2>&1 && { ok=1; break; }
    sleep 1
done
if [ "$ok" = 1 ]; then echo "OK    the console answers on https://$MGMT_IP/"; else echo "FAIL  the console does not answer on https://$MGMT_IP/api/health"; problems=1; fi
dnsone-ctl rpz build >/dev/null 2>&1 || true
# The query log reports in once a minute: wait for its first report before the health check.
for _ in $(seq 18); do
    dnsone-ctl status 2>/dev/null | grep -q 'dnsone-querylog is not running' || break
    sleep 5
done
dnsone-ctl status || true
[ "$problems" = 0 ] || fail "some services are not running (above). Fix the cause and run this script again."

date -Is > "$MARKER"
cat <<EOF

DNSOne $(cat $REL/VERSION) is installed.

  Console        https://$CONSOLE_FQDN/   (or https://$MGMT_IP/)
  User           $ADMIN_USER
  Password       $ADMIN_PASSWORD
                 (also in $SECRETS; change it in My profile, then delete the ADMIN_PASSWORD line)
  DNS            $SERVER_IP port 53

Next:
  - Settings -> DNS server: your customer networks and NAT addresses (until then: the private ranges$([ -n "$CLIENT_NETWORKS" ] && echo " and $CLIENT_NETWORKS")).
  - The certificate is self-signed: put your own in /etc/ssl/dnsone/dnsone.crt and .key, then systemctl reload nginx.
$([ "$use_ufw" = 1 ] && echo "  - ufw is on: SSH and the console only from $MGMT_NET." || echo "  - Settings -> Firewall: turn on DNSOne's firewall (SSH and the console from your management networks only).")
  - Ad-blocking -> Lists: add a first blocklist.
  - Status: dnsone-status. Updates: sudo dnsone-update (or Settings -> Overview).
  - Backups run daily to /var/backups/dnsone; copy them off the server too.
EOF
