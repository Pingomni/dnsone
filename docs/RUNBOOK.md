# DNSOne runbook: Phase 1, single server

Installs DNSOne on a fresh **Ubuntu 24.04 LTS** server, as `root`, in the delivery order of the brief.
Every block is meant to be pasted as-is. Values you must choose are in **step 0**. Secrets are generated
once and kept in `/root/dnsone-secrets.env` (mode 0600), which each step reads.

```
clients ──53/udp,tcp──▶ dnsdist ──▶ PowerDNS Recursor 127.0.0.1:5300 ──▶ BIND 127.0.0.1:5301
                          │            (cache + RPZ ad-blocking)            (authoritative zones)
internet resolvers ──53──▶┘ hosted zones only ──────────────────────────────▶ BIND
operators ──443──▶ nginx ──▶ DNSOne API 127.0.0.1:8100 ──▶ MySQL 8 (source of truth)
                                         └─ writes zone files, zones.conf, RPZ ─▶ rndc / rec_control
```

Tested versions (the Ubuntu 24.04 packages): BIND 9.18.39, PowerDNS Recursor 4.9.3, dnsdist 1.8.3,
MySQL 8.0.46, nginx 1.24, Python 3.12, Node.js 22 (build only).

---

## 0. Choose the values for this server

```bash
cat > /root/dnsone-secrets.env <<'EOF'
SERVER_IP=203.0.113.53            # the address clients send DNS to (dnsdist listens here, port 53)
MGMT_IP=10.10.0.53                # the address the web console listens on (nginx, port 443)
MGMT_NET=10.10.0.0/24             # who may reach SSH and the console
CONSOLE_FQDN=dns1.example.net     # host name of the console (for the TLS certificate)
EOF
chmod 600 /root/dnsone-secrets.env
nano /root/dnsone-secrets.env     # set the four values above
```

Generate the secrets (once):

```bash
cat >> /root/dnsone-secrets.env <<EOF
DB_PASS=$(openssl rand -hex 24)
REC_API_KEY=$(openssl rand -hex 24)
DIST_API_KEY=$(openssl rand -hex 24)
DIST_WEB_PASSWORD=$(openssl rand -hex 24)
DIST_CONSOLE_KEY=$(head -c32 /dev/urandom | base64)
EOF
. /root/dnsone-secrets.env && echo "secrets ready for $SERVER_IP"
```

Get the project onto the server at `/opt/dnsone` (git clone, or `rsync -a dnsone/ root@server:/opt/dnsone/`), then:

```bash
chown -R root:root /opt/dnsone && chmod -R go-w /opt/dnsone
```

---

## 1. Project layout and MySQL schema

### Layout

```
/opt/dnsone/
  backend/            FastAPI app (dnsone/), migrations/ (SQL), tests/
  frontend/           React SPA (RadiusOne theme), built into frontend/dist
  deploy/             bind/, recursor/, dnsdist/, systemd/, nginx/, sudoers/, logrotate/, env/, ufw.sh
  ops/                dnsone-backup, dnsone-status, dnsone-ctl (wrapper)
  docs/RUNBOOK.md     this file
```

| Path on the server | Owner | Purpose |
|---|---|---|
| `/etc/dnsone/dnsone.env` | root:dnsone 0640 | settings and secrets for the API and timers |
| `/var/lib/bind/zones/` | dnsone:bind 2750 | generated zone files (`<zone>.zone`, previous copy `.prev`) |
| `/etc/bind/dnsone/` | dnsone:bind 2750 | generated `zones.conf`, DNSOne's rndc key |
| `/var/lib/dnsone/rpz/dnsone.rpz`, `dnsone-allow.rpz` | dnsone 0644 | generated RPZ of the Default group (block zone, allow zone) |
| `/var/lib/dnsone/rpz/dnsone-g<id>.rpz`, `dnsone-g<id>-allow.rpz` | dnsone 0644 | the same for each other client group with blocking on |
| `/var/lib/dnsone/rpz/zones.lua` | dnsone 0644 | which RPZ files `recursor.lua` loads, in order |
| `/var/lib/dnsone/recursor/forward-zones.conf` | dnsone 0644 | hosted zones → local BIND |
| `/var/lib/dnsone/recursor/policy.lua`, `policy.json` | dnsone 0644 | client groups, pauses, regex rules: read by `/etc/powerdns/dnsone.lua` and dnsone-querylog |
| `/var/lib/dnsone/recursor/allow-from.conf` | dnsone 0644 | customer networks the Recursor serves (Settings → DNS server) |
| `/var/lib/dnsone/dnsdist/auth-zones.txt` | dnsone 0644 | hosted zones dnsdist answers for the public |
| `/var/lib/dnsone/dnsdist/settings.lua` | dnsone 0644 | customer networks, NAT addresses, rate limits, regex rules for dnsdist |
| `/var/lib/dnsone/blocklists/` | dnsone 0750 | parsed blocklist copies |
| `/var/log/dnsone/dnsone.log` | dnsone:adm 0640 | application log (rotated daily, 14 kept) |
| `/var/backups/dnsone/` | root 0700 | daily backups (14 days) |

### Packages

Node.js is only needed to build the console; Ubuntu's own nodejs (18) is too old for Vite 8, so it
comes from NodeSource. (You can also build `frontend/dist` on a workstation and copy it.)

```bash
apt-get update
apt-get install -y bind9 bind9-utils bind9-dnsutils pdns-recursor dnsdist mysql-server-8.0 \
    nginx python3-venv python3-dev build-essential sudo ufw openssl jq curl ca-certificates
curl -fsSL https://deb.nodesource.com/setup_22.x -o /root/nodesource_setup.sh
less /root/nodesource_setup.sh        # read it before running it
bash /root/nodesource_setup.sh && apt-get install -y nodejs
node --version                        # v22.x
```

### Service user and directories

```bash
adduser --system --group --no-create-home --home /nonexistent dnsone
usermod -aG bind dnsone
install -d -o dnsone -g bind   -m 2750 /etc/bind/dnsone
# Group-writable: BIND writes the signed copy of DNSSEC-signed zones (<zone>.zone.signed) beside DNSOne's file.
install -d -o dnsone -g bind   -m 2770 /var/lib/bind/zones
# DNSSEC signing keys, written and read by BIND only (DNSONE_BIND_KEY_DIR).
install -d -o bind   -g bind   -m 0750 /var/lib/bind/keys
install -d -o dnsone -g dnsone -m 0755 /var/lib/dnsone /var/lib/dnsone/rpz /var/lib/dnsone/recursor /var/lib/dnsone/dnsdist
install -d -o dnsone -g dnsone -m 0750 /var/lib/dnsone/blocklists
install -d -o dnsone -g adm    -m 0750 /var/log/dnsone
install -d -o root   -g dnsone -m 0750 /etc/dnsone
install -d -o root   -g root   -m 0700 /var/backups/dnsone
```

### Application

```bash
cd /opt/dnsone/backend
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e .
cd /opt/dnsone/frontend
npm ci && npm run build               # → frontend/dist
install -m 0755 /opt/dnsone/ops/dnsone-ctl /usr/local/sbin/dnsone-ctl
install -m 0755 /opt/dnsone/ops/dnsone-status /usr/local/sbin/dnsone-status
```

### Database and schema

```bash
. /root/dnsone-secrets.env
mysql <<SQL
CREATE DATABASE IF NOT EXISTS dnsone CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER IF NOT EXISTS 'dnsone'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON dnsone.* TO 'dnsone'@'127.0.0.1';
SQL

install -o root -g dnsone -m 0640 /opt/dnsone/deploy/env/dnsone.env /etc/dnsone/dnsone.env
sed -i -e "s#CHANGE_ME_DB_PASSWORD#${DB_PASS}#" -e "s#CHANGE_ME_RECURSOR_API_KEY#${REC_API_KEY}#" \
       -e "s#CHANGE_ME_DNSDIST_API_KEY#${DIST_API_KEY}#" -e "s#^DNSONE_NODE_NAME=.*#DNSONE_NODE_NAME=$(hostname -s)#" \
       /etc/dnsone/dnsone.env
# Optional: show times in your timezone, e.g.
# sed -i 's#^DNSONE_TIMEZONE=.*#DNSONE_TIMEZONE=Europe/Tirane#' /etc/dnsone/dnsone.env

dnsone-ctl migrate                    # applies backend/migrations/0001_initial.sql
dnsone-ctl create-admin admin --email you@example.net    # asks for a password (12+ characters)
```

The schema (`backend/migrations/0001_initial.sql`) creates `zones`, `records`, `rpz_rules`,
`blocklists`, `audit_log`, `users`, `roles`, `sessions`, `settings` and `stats_samples` (InnoDB, utf8mb4),
with the indexes `records(zone_id, name, type)`, `records(zone_id, type)`, a unique RR hash per zone,
`rpz_rules(pattern)` unique and `rpz_rules(enabled, action)`. Later releases add numbered files;
`dnsone-ctl migrate` applies the new ones (take a backup first: `/opt/dnsone/ops/dnsone-backup`).

### Verify step 1

- [ ] `dnsone-ctl migrate --status` lists `applied  0001_initial.sql`
- [ ] `mysql -e "SELECT name, JSON_LENGTH(permissions) FROM dnsone.roles"` shows admin / operator / viewer
- [ ] `mysql -e "SHOW INDEX FROM dnsone.records"` includes `idx_records_zone_name_type`
- [ ] `ls /opt/dnsone/frontend/dist/index.html` exists

---

## 2. Server configuration: BIND, Recursor, dnsdist, systemd, firewall

### BIND (authoritative only, 127.0.0.1:5301)

```bash
install -o root -g bind -m 0644 /opt/dnsone/deploy/bind/named.conf.options /etc/bind/named.conf.options
install -o root -g bind -m 0644 /opt/dnsone/deploy/bind/named.conf.local   /etc/bind/named.conf.local
[ -f /etc/bind/rndc.key ] || rndc-confgen -a
tsig-keygen -a hmac-sha256 dnsone-rndc > /etc/bind/dnsone/dnsone-rndc.key
chown root:bind /etc/bind/dnsone/dnsone-rndc.key && chmod 0640 /etc/bind/dnsone/dnsone-rndc.key
install -o dnsone -g bind -m 0640 /dev/null /etc/bind/dnsone/zones.conf
named-checkconf && systemctl restart named && systemctl enable named
```

### PowerDNS Recursor (cache + RPZ, 127.0.0.1:5300)

The Recursor validates DNSSEC for every client (`dnssec=validate`). `dnsone.lua` (the
`lua-dns-script`) applies client groups, paused blocking and regex rules from data DNSOne generates;
the file itself never changes. `recursor.lua` loads the RPZ files listed in `zones.lua` and adds two things:
- the root KSK-2024 trust anchor, which Ubuntu's Recursor 4.9.3 lacks. Without it every answer fails
  validation, now that the root zone is signed with that key;
- negative trust anchors for the hosted zones (read from a file the zone generator maintains).
  DNSOne serves them unsigned, so without the anchors a private or not-yet-delegated zone would be
  SERVFAIL for customers.

```bash
. /root/dnsone-secrets.env
install -o root -g pdns -m 0640 /opt/dnsone/deploy/recursor/recursor.conf /etc/powerdns/recursor.conf
install -o root -g pdns -m 0644 /opt/dnsone/deploy/recursor/recursor.lua  /etc/powerdns/recursor.lua
install -o root -g pdns -m 0644 /opt/dnsone/deploy/recursor/dnsone.lua    /etc/powerdns/dnsone.lua
sed -i "s#CHANGE_ME_RECURSOR_API_KEY#${REC_API_KEY}#" /etc/powerdns/recursor.conf
# Customer networks until DNSOne writes them from Settings → DNS server (dnsone-ctl sync, below).
install -o root -g root -m 0644 /opt/dnsone/deploy/dnsone/client-networks.conf /etc/dnsone/client-networks.conf
nano /etc/dnsone/client-networks.conf  # your customer ranges, including public ones behind NAT
grep -v '^#' /etc/dnsone/client-networks.conf | install -o dnsone -g dnsone -m 0644 /dev/stdin /var/lib/dnsone/recursor/allow-from.conf
install -o dnsone -g dnsone -m 0644 /dev/null /var/lib/dnsone/recursor/forward-zones.conf
install -o dnsone -g dnsone -m 0644 /dev/null /var/lib/dnsone/recursor/negative-trust-anchors.txt
printf '$TTL 60\n@ IN SOA localhost. hostmaster.localhost. 1 3600 600 86400 60\n@ IN NS localhost.\n' \
    | install -o dnsone -g dnsone -m 0644 /dev/stdin /var/lib/dnsone/rpz/dnsone.rpz
systemctl restart pdns-recursor && systemctl enable pdns-recursor
```

### dnsdist (port 53: ACL, rate limiting, routing)

Only the listen addresses (`CHANGE_ME_SERVER_IP`) and keys are set in the file. Customer networks,
NAT addresses (CGNAT gateways that carry many customers), rate limits and public authoritative DNS
are set in the console, *Settings → DNS server*: DNSOne writes `/var/lib/dnsone/dnsdist/settings.lua`
and dnsdist applies it within 2 seconds. Until then dnsdist uses the networks in
`/var/lib/dnsone/recursor/allow-from.conf` (created from `/etc/dnsone/client-networks.conf` above).

```bash
. /root/dnsone-secrets.env
install -o root -g _dnsdist -m 0640 /opt/dnsone/deploy/dnsdist/dnsdist.conf /etc/dnsdist/dnsdist.conf
sed -i -e "s#CHANGE_ME_SERVER_IP#${SERVER_IP}#" -e "s#CHANGE_ME_DNSDIST_API_KEY#${DIST_API_KEY}#" \
       -e "s#CHANGE_ME_DNSDIST_WEB_PASSWORD#${DIST_WEB_PASSWORD}#" -e "s#CHANGE_ME_DNSDIST_CONSOLE_KEY#${DIST_CONSOLE_KEY}#" \
       /etc/dnsdist/dnsdist.conf
install -o dnsone -g dnsone -m 0644 /dev/null /var/lib/dnsone/dnsdist/auth-zones.txt
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf && systemctl restart dnsdist && systemctl enable dnsdist
```

### sudo (Recursor reloads), systemd units, log rotation

```bash
install -o root -g root -m 0440 /opt/dnsone/deploy/sudoers/dnsone /etc/sudoers.d/dnsone
visudo -cf /etc/sudoers.d/dnsone
install -m 0644 /opt/dnsone/deploy/systemd/dnsone-*.service /opt/dnsone/deploy/systemd/dnsone-*.timer /etc/systemd/system/
install -m 0644 /opt/dnsone/deploy/logrotate/dnsone /etc/logrotate.d/dnsone
systemctl daemon-reload
systemctl enable --now dnsone-api.service
systemctl enable --now dnsone-querylog.service
systemctl enable --now dnsone-sync.timer dnsone-reconcile.timer dnsone-rpz.timer dnsone-stats.timer dnsone-backup.timer
dnsone-ctl sync                       # writes the runtime files for dnsdist and the Recursor
```

### nginx (HTTPS console)

A self-signed certificate gets you started; replace it with your CA's certificate (same paths) or certbot.

```bash
. /root/dnsone-secrets.env
install -d -m 0750 /etc/ssl/dnsone
openssl req -x509 -newkey rsa:3072 -nodes -days 825 -subj "/CN=${CONSOLE_FQDN}" \
    -addext "subjectAltName=DNS:${CONSOLE_FQDN},IP:${MGMT_IP}" \
    -keyout /etc/ssl/dnsone/dnsone.key -out /etc/ssl/dnsone/dnsone.crt
install -m 0644 /opt/dnsone/deploy/nginx/dnsone-proxy.conf /etc/nginx/snippets/dnsone-proxy.conf
install -m 0644 /opt/dnsone/deploy/nginx/dnsone.conf /etc/nginx/sites-available/dnsone
sed -i -e "s#CHANGE_ME_MGMT_IP#${MGMT_IP}#g" -e "s#CHANGE_ME_FQDN#${CONSOLE_FQDN}#g" /etc/nginx/sites-available/dnsone
ln -sf /etc/nginx/sites-available/dnsone /etc/nginx/sites-enabled/dnsone
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
```

### Firewall (ufw)

```bash
. /root/dnsone-secrets.env
MGMT_NET="$MGMT_NET" /opt/dnsone/deploy/ufw.sh
```

Opens 53/udp and 53/tcp to everyone (dnsdist decides who may recurse), and 22 and 443 (80 redirects)
to `MGMT_NET` only. MySQL, BIND (5301), the Recursor (5300) and every API stay on loopback.

### Verify step 2

```bash
. /root/dnsone-secrets.env
named-checkconf && echo "named.conf OK"
rndc status | head -3
rndc -k /etc/bind/dnsone/dnsone-rndc.key status | grep 'server is up'     # DNSOne's own key works
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf
dig @"$SERVER_IP" one.one.one.one A +short          # from a CLIENT_NETWORKS address: answers
dig @"$SERVER_IP" example.com A +dnssec | grep flags # 'ad' flag: DNSSEC validation works
dig @"$SERVER_IP" dnssec-failed.org A +noadflag | grep status  # SERVFAIL: broken signatures are refused
dig @"$SERVER_IP" +notcp example.com ANY | grep flags # 'tc': ANY over UDP is pushed to TCP
curl -s -H "X-API-Key: $REC_API_KEY" http://127.0.0.1:8082/api/v1/servers/localhost | jq -r .version
curl -s -H "X-API-Key: $DIST_API_KEY" http://127.0.0.1:8083/api/v1/servers/localhost | jq -r .version
systemctl is-active named pdns-recursor dnsdist dnsone-api nginx
curl -sk "https://$MGMT_IP/api/health"              # {"status":"ok"} or "warning" until the RPZ is built
ufw status verbose
```

- [ ] From an address **outside** the customer networks: `dig @SERVER_IP one.one.one.one` → `REFUSED` (not an open resolver)
- [ ] `dnsone-ctl status` shows *Client policies* and *DNS server settings* OK: the Recursor and dnsdist run DNSOne's data
- [ ] The console opens at `https://CONSOLE_FQDN/` and the admin can sign in

---

## 3. Zone generator

How it works (`backend/dnsone/zonegen.py`):

1. Every API write bumps the zone's `revision` and marks it `pending` in the same transaction; after
   the commit, a background task publishes it. `dnsone-reconcile.timer` (every 5 minutes) publishes
   anything still behind, re-creates missing files and removes files of deleted zones.
2. Publishing renders the zone with serial `YYYYMMDDnn` (`max(today·100, last + 1)`), writes it to a
   temporary file next to the live one and runs
   `named-checkzone -k fail -n fail -m fail -M fail -S fail -i local`. **If the check fails, the live
   file is not touched**; the zone shows *publish failed* with the checker's output, and BIND keeps
   serving the last good serial.
3. The file is renamed into place (atomic; the old one is kept as `.prev`), then `rndc reload <zone>`
   (or `rndc reconfig` for a new zone, after `zones.conf` passes `named-checkconf`). DNSOne then asks
   BIND for the SOA; **if BIND did not load the new serial, `.prev` is restored and reloaded.**
4. The Recursor's cache for the zone is wiped, so customers see the change at once.
5. When the set of served zones changes, `zones.conf`, the Recursor's forward zones and negative trust
   anchors (`rec_control reload-zones`, `add-nta`, `clear-nta`) and dnsdist's public list are updated.

All of this runs under a MySQL advisory lock, so API workers, timers and the CLI never collide.

Commands:

```bash
dnsone-ctl zones list
dnsone-ctl zones publish example.net          # validate + write + reload one zone now
dnsone-ctl zones reconcile                    # what the timer runs
dnsone-ctl zones reconcile --force            # rewrite every zone (e.g. after restoring files)
systemctl list-timers 'dnsone-*'
```

### Verify step 3

Create a test zone through the API (the same calls the console makes):

```bash
. /root/dnsone-secrets.env
B="https://$MGMT_IP"; J=/root/.dnsone-cookies
read -rsp "admin password: " PW; echo
CSRF=$(curl -sk -c $J -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"$PW\"}" $B/api/auth/login | jq -r .csrf)
api() { curl -sk -b $J -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -X "$1" "$B$2" ${3:+-d "$3"}; echo; }

api POST /api/zones '{"name":"dnsone-test.example","soa_rname":"hostmaster@dnsone-test.example",
  "nameservers":[{"host":"ns1","address":"192.0.2.53"},{"host":"ns2.example.net"}]}'
ZID=$(api GET '/api/zones?q=dnsone-test' | jq '.rows[0].id')
api POST /api/zones/$ZID/records '{"name":"www","type":"A","value":"192.0.2.10","ttl":300}'
sleep 2
```

- [ ] `dig @127.0.0.1 -p 5301 dnsone-test.example SOA +short` shows serial `YYYYMMDDnn` (today)
- [ ] `dig @"$SERVER_IP" www.dnsone-test.example A +short` → `192.0.2.10` (through dnsdist → Recursor → BIND;
      dig asks for validation, so this also checks the zone's negative trust anchor)
- [ ] `rec_control get-ntas` lists `dnsone-test.example`
- [ ] `named-checkzone dnsone-test.example /var/lib/bind/zones/dnsone-test.example.zone` → `OK`
- [ ] `rndc zonestatus dnsone-test.example | grep serial`
- [ ] Rollback: add an in-zone NS without an address. The zone goes to *publish failed*, and the
      served serial does not change:
      ```bash
      BAD=$(api POST /api/zones/$ZID/records '{"name":"@","type":"NS","value":"ns9"}' | jq .id); sleep 2
      api GET /api/zones/$ZID | jq '{publish_state, published_serial, last_error}'
      dig @127.0.0.1 -p 5301 dnsone-test.example SOA +short
      api DELETE /api/zones/$ZID/records/$BAD
      ```
- [ ] Validation: `api POST /api/zones/$ZID/records '{"name":"@","type":"CNAME","value":"x.example.net"}'`
      → 422 *A CNAME cannot be at the zone apex*

---

## 4. Backend API

FastAPI under `/api`, documented at `https://CONSOLE_FQDN/api/docs` (OpenAPI). It runs as
`dnsone-api.service` (uvicorn, two workers, 127.0.0.1:8100) behind nginx.

| Area | Endpoints |
|---|---|
| Auth | `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, `POST /api/auth/password` |
| Zones | `GET/POST /api/zones`, `GET/PATCH/DELETE /api/zones/{id}`, `POST /api/zones/{id}/publish`, `GET /api/zones/{id}/preview` |
| Records | `GET/POST /api/zones/{id}/records`, `PATCH/DELETE /api/zones/{id}/records/{rid}` |
| RPZ | `GET /api/rpz/status`, `PUT /api/rpz/policy`, `POST /api/rpz/build`, `GET /api/rpz/lookup?domain=` |
| RPZ rules | `GET/POST /api/rpz/rules`, `POST /api/rpz/rules/import`, `PATCH/DELETE /api/rpz/rules/{id}` |
| Blocklists | `GET/POST /api/rpz/blocklists`, `PATCH/DELETE /api/rpz/blocklists/{id}`, `POST /api/rpz/blocklists/{id}/refresh` |
| Stats | `GET /api/stats/summary?hours=24`, `GET /api/dashboard` |
| Audit | `GET /api/audit?q=&actor=&entity=&action=&from=&to=` |
| Users | `GET/POST /api/users`, `PATCH/DELETE /api/users/{id}`, `GET /api/roles` |
| Health | `GET /api/health` (public, status only), `GET /api/system/health` (details, signed in) |

- **Lists** take `page` and `size` (≤ 500) and return `{rows, total, page, pages, size}`; each has a
  search (`q`) and filters.
- **Errors** are `{"message": "...", "errors": {"field": "..."}}` (422 validation, 409 conflict, 401, 403).
- **Validation**: names (LDH, IDN to punycode, 63/253 limits, BIND check-names), per-type values
  (IPv4/IPv6, targets, MX/SRV priority, SRV `_service._proto` and `weight port target`, CAA
  `flags tag "value"`, TXT up to 4000 bytes split into 255-byte strings), TTL 60–604800, SOA timer
  bounds, no CNAME at the apex, a CNAME alone at its name, at least one apex NS, no duplicate records.
- **Security**: Argon2id passwords; server-side sessions in MySQL (HttpOnly, Secure, SameSite=Strict
  cookie); a CSRF token on every write; a lockout after 5 failures (15 minutes); nginx limits
  `/api/auth/login` to 10 per minute per address. SQLAlchemy binds every value (no string-built SQL).
- **Audit**: every write adds an `audit_log` row in the same transaction (actor, action, entity, id,
  JSON payload with before/after, client IP). Passwords are never logged.
- **Roles**: `admin` (everything), `operator` (zones, ad-blocking, audit), `viewer` (read-only).

### Verify step 4

```bash
curl -sk "$B/api/zones" | jq .message                              # "Your session has expired..." (401)
api GET '/api/zones?q=test&size=10' | jq '{total, pages}'
api GET /api/zones/$ZID/records | jq '.rows[] | [.name, .type, .value] | @tsv' -r
curl -sk -b $J -X POST "$B/api/zones" -d '{}' | jq .message      # 403: no CSRF token
api GET '/api/audit?entity=record' | jq '.rows[0] | {actor, action, payload}'
```

- [ ] Five wrong passwords lock the account for 15 minutes (`dnsone-ctl create-admin admin` resets it)
- [ ] Signed in as a `viewer`, writes return 403 (create one under *Settings → Users*)

---

## 5. RPZ ad-blocking pipeline

How it works (`backend/dnsone/rpz.py`, `runtime.py`, `deploy/recursor/dnsone.lua`):

1. **Refresh** (`dnsone-rpz.timer`, every 6 hours, or *Refresh* in the console) downloads each enabled
   blocklist with a conditional GET (ETag / Last-Modified, 64 MB cap). It parses hosts files
   (`0.0.0.0 name`), plain domain lists and simple Adblock rules (`||name^`), skips local names,
   de-duplicates, and stores the sorted set. A failed download or an empty result keeps the previous copy.
2. **Build** writes two zones per *client group* with blocking on. The allow zone holds
   `rpz-passthru.` for allow rules and *allowlists* (downloaded lists of names never blocked); the
   block zone holds the group's blocklists and block rules: `name CNAME .` (NXDOMAIN), `CNAME *.`
   (NODATA), `A 0.0.0.0` + `AAAA ::` (null IP) or a walled-garden A/AAAA/CNAME, per the policy and per
   rule. Rules for every group apply to all; a group's own rule for the same name wins. With *block
   subdomains* on (the default), `*.name` is added for list entries and exact rules. The allow zone
   is loaded first, without the "Blocked" extended DNS error (the Recursor adds a zone's error code
   to passthru hits too).
3. Every file is checked with `named-checkzone`, renamed into place and loaded with
   `rec_control reload-lua-config` (no restart, no lost queries). The Recursor's API must then report
   the new serial for every zone; if the reload fails, the previous files are put back. Names whose
   policy changed are wiped from the Recursor's cache, so a whitelist entry works immediately.
4. **Per query**, the policy script picks the client's group (the most specific network in
   *Client groups*; Default otherwise) and discards every other group's zones. Paused blocking (for
   everyone or a group, N minutes or until resumed) discards all of them. *Regex rules*
   (POSIX extended, case-insensitive) are matched by dnsdist, which tells the Recursor which rules
   matched in a PROXY protocol value; a regex *allow* lifts every block for the client's group, a
   regex *block* answers with the block policy unless an RPZ entry (an allow rule, say) matched.
   Group, pause and regex verdict are part of the packet-cache key, so changes to them apply at once.

```bash
dnsone-ctl rpz build        # rebuild from stored lists and rules
dnsone-ctl rpz refresh      # download every list, then build (what the timer runs)
```

Add a first blocklist in the console (*Ad-blocking → Lists → Add a list*), for example a
hosts-format list such as `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`. Client
groups (*Client groups*): e.g. *Family* with an adult-content list, *Business* with blocking off.
Each extra group with blocking on holds its own copy of its lists in the Recursor's memory.

```bash
dnsone-ctl rpz pause --minutes 15                   # pause for everyone (or --group NAME); 0 = until resumed
dnsone-ctl rpz resume
```

### Verify step 5

```bash
api POST /api/rpz/rules '{"pattern":"blocked-test.example","action":"block"}'; sleep 3
dig @"$SERVER_IP" blocked-test.example A | grep status        # NXDOMAIN (the default policy)
dig @"$SERVER_IP" x.blocked-test.example A | grep status      # NXDOMAIN too: subdomains are blocked (Block policy)
api POST /api/rpz/rules '{"pattern":"blocked-test.example","action":"allow"}'  # 409: one rule per name
api GET '/api/rpz/lookup?domain=blocked-test.example' | jq
curl -s -H "X-API-Key: $REC_API_KEY" http://127.0.0.1:8082/api/v1/servers/localhost/rpzstatistics | jq 'map_values(.serial)'
api POST /api/rpz/rules '{"pattern":"^regex-test[0-9]+\\.example$","match_type":"regex","action":"block"}'; sleep 3
dig @"$SERVER_IP" regex-test7.example A +noall +comments | grep -E 'status|EDE'  # NXDOMAIN, EDE 15 Blocked
api GET /api/rpz/status | jq .state                            # serial matches rpzstatistics
named-checkzone -k ignore -i none rpz.dnsone /var/lib/dnsone/rpz/dnsone.rpz
systemctl list-timers dnsone-rpz.timer
```

- [ ] With the policy set to *walled garden* `192.0.2.80`: `dig @SERVER_IP blocked-test.example A +short` → `192.0.2.80`
- [ ] An *allow* rule for a listed name: `dig` returns the real answer within seconds, without an EDE "Blocked"
- [ ] A client group with blocking off, holding a test client's address: that client gets real answers for blocked names
- [ ] *Pause blocking* for 5 minutes: blocked names resolve at once, and are blocked again after *Resume*

---

## 6. Web console

The console is RadiusOne's interface: its stylesheet and shared components (`app.css`, `ui`,
`table`, `confirm`, `tabs`, `Icon`, `metrics`, `LivePanel`, `lib/*`) are copied **unchanged** into
`frontend/src/` by `npm run sync-radiusone`. RadiusOne imports Inertia; DNSOne resolves the same
import to `src/shim/inertia.tsx`, a small client-side router, so those files run as-is in an SPA that
talks to the REST API. DNSOne's own parts follow the same design language: the layout (RadiusOne's
`AppLayout` with DNS navigation and the DNSOne mark), the pages, and `src/dnsone.css` (toasts, form
dialogs, the inline record editor, built from RadiusOne's tokens only).

Screens: Dashboard (key figures, service health, queries per hour, recent changes) · Zones (search,
filters, publish state) · Zone editor (records with inline add/edit/disable/delete, SOA settings,
zone file preview, *Publish now*) · Query log (live log with filters, per-client view, block/allow
from a row; top lists, query types, reply codes, 30-day history) · Ad-blocking (RPZ status, pause,
rules (domains and regexes, per group) with on/off toggles and import, blocklists and allowlists,
block policy, *Check a domain*) · Client groups (networks, lists, client lookup) · Audit log ·
Settings (Overview; Users with two-factor reset; DNS server; Privacy; Backup and restore; Cluster) ·
My profile (password, two-factor sign-in with recovery codes, app passwords).
Light and dark themes, and phone layouts, as in RadiusOne.

After a RadiusOne UI update:

```bash
cd /opt/dnsone/frontend && RADIUSONE_DIR=/path/to/radiusone npm run sync-radiusone && npm run build
```

### Verify step 6

- [ ] Sign in at `https://CONSOLE_FQDN/`; a wrong password shows the error on the card
- [ ] Zones → *New zone* → the zone opens with *publishing*, then *published*
- [ ] Add a record in the top row; edit it inline (Enter saves, Escape cancels); delete asks first
- [ ] An invalid record (apex CNAME) shows the reason under the row and nothing is saved
- [ ] Ad-blocking → toggle a rule off and on; the status panel follows the rebuild
- [ ] Audit log shows each change with the operator's name
- [ ] The browser console shows no Content-Security-Policy errors

---

## 7. Operations

### Backups (daily, 14 days)

`dnsone-backup.timer` runs `/opt/dnsone/ops/dnsone-backup` at 03:15. Each run writes
`/var/backups/dnsone/YYYYmmdd-HHMMSS/` with `dnsone.sql.gz` (consistent `mysqldump --single-transaction`),
`files.tar.gz` (zones, `/etc/bind`, `/etc/dnsone`, `/etc/powerdns`, `/etc/dnsdist`, the RPZ, nginx site,
TLS files) and `SHA256SUMS`. The dump and archive are verified before the run is kept. Runs older than
14 days are deleted, but the newest three are always kept. Copy the directory off the server as well.

```bash
. /root/dnsone-secrets.env
printf '[client]\nuser=dnsone\npassword=%s\nhost=127.0.0.1\n' "$DB_PASS" | install -m 0600 /dev/stdin /etc/dnsone/backup.cnf
systemctl start dnsone-backup.service && journalctl -u dnsone-backup -n 5 --no-pager
ls -l /var/backups/dnsone/
```

### Restore from a backup

```bash
R=/var/backups/dnsone/20261022-031500          # the run to restore
(cd $R && sha256sum -c SHA256SUMS)
systemctl stop dnsone-api dnsone-reconcile.timer dnsone-rpz.timer
zcat $R/dnsone.sql.gz | mysql dnsone
mkdir -p /root/restore && tar -xzf $R/files.tar.gz -C /root/restore   # inspect, copy back what you need
systemctl start dnsone-api dnsone-reconcile.timer dnsone-rpz.timer
dnsone-ctl zones reconcile --force && dnsone-ctl rpz build            # regenerate every file from MySQL
```

### Health and status

```bash
dnsone-status              # systemd state of every unit + DNSOne's probes; exit 0 ok, 1 error, 2 warning
dnsone-ctl status          # the probes only: MySQL, rndc, BIND over DNS, Recursor/dnsdist APIs, publishing, RPZ, disk
curl -sk https://$MGMT_IP/api/health                # {"status":"ok"}; HTTP 503 on errors (for monitoring)
```

### Logs

```bash
journalctl -u dnsone-api -f                         # API
journalctl -u 'dnsone-*' --since today              # API and timers
tail -f /var/log/dnsone/dnsone.log                  # the same, as a file (rotated daily, 14 kept)
journalctl -u named -u pdns-recursor -u dnsdist --since -1h
dnsdist -c -e 'showServers()'                       # dnsdist console
dnsdist -c -e 'topClients(10)'
rec_control get-all | grep -E 'questions|cache-hits|policy-result'
```

### Upgrading DNSOne

```bash
/opt/dnsone/ops/dnsone-backup
cd /opt/dnsone && git pull          # or rsync the new release
cd backend && .venv/bin/pip install -e . && dnsone-ctl migrate
cd ../frontend && npm ci && npm run build
systemctl restart dnsone-api dnsone-querylog && dnsone-status
```

#### From 1.0 to 1.1 (client groups, regex rules, two-factor, DNS server settings, clustering)

After the steps above, install the new and changed system files (keys and addresses are kept by
re-applying the same `sed` lines as in step 2):

```bash
. /root/dnsone-secrets.env
install -o root -g pdns -m 0644 /opt/dnsone/deploy/recursor/dnsone.lua   /etc/powerdns/dnsone.lua
install -o root -g pdns -m 0644 /opt/dnsone/deploy/recursor/recursor.lua /etc/powerdns/recursor.lua
install -o root -g pdns -m 0640 /opt/dnsone/deploy/recursor/recursor.conf /etc/powerdns/recursor.conf
sed -i "s#CHANGE_ME_RECURSOR_API_KEY#${REC_API_KEY}#" /etc/powerdns/recursor.conf
grep -v '^#' /etc/dnsone/client-networks.conf | install -o dnsone -g dnsone -m 0644 /dev/stdin /var/lib/dnsone/recursor/allow-from.conf
cp /etc/dnsdist/dnsdist.conf /root/dnsdist.conf.1.0
install -o root -g _dnsdist -m 0640 /opt/dnsone/deploy/dnsdist/dnsdist.conf /etc/dnsdist/dnsdist.conf
sed -i -e "s#CHANGE_ME_SERVER_IP#${SERVER_IP}#" -e "s#CHANGE_ME_DNSDIST_API_KEY#${DIST_API_KEY}#" \
       -e "s#CHANGE_ME_DNSDIST_WEB_PASSWORD#${DIST_WEB_PASSWORD}#" -e "s#CHANGE_ME_DNSDIST_CONSOLE_KEY#${DIST_CONSOLE_KEY}#" \
       /etc/dnsdist/dnsdist.conf
install -o root -g root -m 0440 /opt/dnsone/deploy/sudoers/dnsone /etc/sudoers.d/dnsone && visudo -cf /etc/sudoers.d/dnsone
install -m 0644 /opt/dnsone/deploy/systemd/dnsone-*.service /opt/dnsone/deploy/systemd/dnsone-*.timer /etc/systemd/system/
install -m 0644 /opt/dnsone/deploy/nginx/dnsone.conf /etc/nginx/sites-available/dnsone
sed -i -e "s#CHANGE_ME_MGMT_IP#${MGMT_IP}#g" -e "s#CHANGE_ME_FQDN#${CONSOLE_FQDN}#g" /etc/nginx/sites-available/dnsone
nginx -t && systemctl reload nginx
systemctl daemon-reload
# Generate the new files first, so the daemons start with them.
dnsone-ctl rpz build && dnsone-ctl sync
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf && systemctl restart pdns-recursor dnsdist
systemctl enable --now dnsone-sync.timer && dnsone-ctl status
```

Then open *Settings → DNS server*: it shows the networks from `/etc/dnsone/client-networks.conf`
(the NAT addresses and limits of the old `dnsdist.conf` are in `/root/dnsdist.conf.1.0`); check them
and *Save*. From then on the console is the place to change them. Existing blocklists and rules
apply to the Default group, as before.

Behaviour changes: allowed names no longer carry the extended DNS error "Blocked"; dnsdist now
picks up new hosted zones for public authoritative DNS (1.0 only saw those present at its start).

#### From 1.1 to 1.2 (DNSSEC, record types, zone import/export, reverse DNS, DoT/DoH, alerts, metrics)

After the general steps above (`dnsone-ctl migrate` applies `0005_zone_features.sql`):

```bash
. /root/dnsone-secrets.env
# BIND writes signed zones beside DNSOne's files, and its keys in /var/lib/bind/keys.
chmod 2770 /var/lib/bind/zones
install -d -o bind -g bind -m 0750 /var/lib/bind/keys
grep -q '^DNSONE_BIND_KEY_DIR=' /etc/dnsone/dnsone.env || echo 'DNSONE_BIND_KEY_DIR=/var/lib/bind/keys' >> /etc/dnsone/dnsone.env
# dnsdist.conf: the 1.2 file adds the (off) DoT/DoH listeners; same values as before.
cp /etc/dnsdist/dnsdist.conf /root/dnsdist.conf.1.1
install -o root -g _dnsdist -m 0640 /opt/dnsone/deploy/dnsdist/dnsdist.conf /etc/dnsdist/dnsdist.conf
sed -i -e "s#CHANGE_ME_SERVER_IP#${SERVER_IP}#" -e "s#CHANGE_ME_DNSDIST_API_KEY#${DIST_API_KEY}#" \
       -e "s#CHANGE_ME_DNSDIST_WEB_PASSWORD#${DIST_WEB_PASSWORD}#" -e "s#CHANGE_ME_DNSDIST_CONSOLE_KEY#${DIST_CONSOLE_KEY}#" \
       /etc/dnsdist/dnsdist.conf
diff /root/dnsdist.conf.1.1 /etc/dnsdist/dnsdist.conf   # only the encrypted-DNS lines (and any local edits to carry over)
# The stats timer now also checks for alerts; the nightly backup includes the DNSSEC keys.
install -m 0644 /opt/dnsone/deploy/systemd/dnsone-stats.service /opt/dnsone/deploy/systemd/dnsone-stats.timer /etc/systemd/system/
systemctl daemon-reload
dnsone-ctl zones reconcile --force       # rewrites zones.conf (now with the DNSOne signing policy)
dnsdist --check-config -C /etc/dnsdist/dnsdist.conf && systemctl restart dnsdist && dnsone-ctl status
```

Nothing changes for existing zones until signing is turned on for them. Then set up alerts
(*Settings → Alerts*) and, if wanted, encrypted DNS (above).

### DNSSEC signing

*Zone → DNSSEC → Sign this zone* adds `dnssec-policy "dnsone"` with inline signing to the zone's
statement in `zones.conf`. DNSOne keeps writing the unsigned file; BIND creates one ECDSA P-256 key
(algorithm 13) in `/var/lib/bind/keys`, signs the zone into `<zone>.zone.signed` and serves that,
re-signing by itself. The key never rolls over, so the DS record at the parent never has to change.

1. Sign the zone; after a few seconds the DNSSEC tab shows the key and the **DS record**.
2. Give the DS record (or the DNSKEY, if the registrar asks for that) to the registrar.
3. *Check again* until the tab says "signed and secure: the parent publishes a matching DS record".

To stop signing, remove the DS at the registrar first and wait a day: DNSOne refuses to stop while
the parent still publishes a DS (resolvers would then see the zone as bogus and answer SERVFAIL).
The zone then goes through `dnssec-policy insecure`, which removes the signatures and keys.

The keys are in the nightly backup (`/var/lib/bind/keys`). A zone restored on a server without its
keys is signed with new ones, and its DS at the registrar must be updated. On clusters, secondaries
transfer the signed zone; only the primary holds keys. Customers still resolve hosted zones without
validation through the local Recursor (negative trust anchors), as before.

```bash
rndc dnssec -status example.com                     # BIND's key states
dig @127.0.0.1 -p 5301 +dnssec www.example.com A    # RRSIG records in the answer
```

### Encrypted DNS (DoT and DoH)

dnsdist can answer DNS over TLS (port 853, what Android's *Private DNS* uses) and DNS over HTTPS
(`https://dns.isp.example/dns-query`, for browsers) on the same addresses as port 53, with the same
rules: customers get the full resolver, everyone else only the hosted zones. Without it, phones and
browsers go to public resolvers and bypass the ISP's resolver, its groups and its ad-blocking.

1. A name for the service, e.g. `dns.isp.example`, with A/AAAA records for the client-facing addresses.
2. A certificate for it, e.g. Let's Encrypt with DNS validation (port 80/443 stay free):
   ```bash
   apt-get install -y certbot
   certbot certonly --manual --preferred-challenges dns -d dns.isp.example   # or a DNS plugin
   install -m 0755 /opt/dnsone/deploy/dnsdist/certbot-deploy-hook /etc/letsencrypt/renewal-hooks/deploy/dnsone-dnsdist
   RENEWED_LINEAGE=/etc/letsencrypt/live/dns.isp.example /etc/letsencrypt/renewal-hooks/deploy/dnsone-dnsdist
   ```
   The hook copies the certificate to `/etc/dnsdist/tls/` and makes dnsdist reload it after every renewal.
3. In `/etc/dnsdist/dnsdist.conf` set `ENCRYPTED_DNS = true` (and `DOH_PORT` if nginx listens on 443 of
   the same address), then `dnsdist --check-config -C /etc/dnsdist/dnsdist.conf && systemctl restart dnsdist`.
4. Open the ports: `ENCRYPTED_DNS_IPS="203.0.113.53" MGMT_NET=… bash /opt/dnsone/deploy/ufw.sh`.

The dashboard's *Encrypted DNS* check lists the listeners and the days left on the certificate; it
warns 14 days before it expires (and alerts, below).

```bash
kdig -d @dns.isp.example +tls example.com                                  # DoT (knot-dnsutils)
# DoH (RFC 8484): example.com A, base64url-encoded; expect 200
curl -s -o /dev/null -w '%{http_code}\n' 'https://dns.isp.example/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE'
```

### Alerts and Prometheus

*Settings → Alerts*: email (SMTP), a webhook (JSON with a `text` field, accepted by Slack, Mattermost,
Rocket.Chat and Teams incoming webhooks) and Telegram (a bot token from @BotFather and the chat id).
Every minute `dnsone-stats.service` runs `dnsone-ctl alerts check` on each node: any health check that
is not ok (a daemon down, zones not publishing, the RPZ build failing, the query log stopped, disks
filling up, the DoT/DoH certificate expiring, a node not syncing), blocklists whose download fails,
and addresses dnsdist is blocking for query floods. A problem is sent once it has lasted *Send after*
minutes, repeated every *Remind every* hours, and followed by a "resolved" message. Checks about
shared data are sent by the primary only. *Save and send a test* checks the channels.

Prometheus scrapes `/api/metrics` on every node with a read-only app password (*My profile → App
passwords*); *Settings → Alerts* shows the scrape configuration.

```bash
dnsone-ctl alerts check      # what is wrong now, and what was sent
dnsone-ctl alerts test       # a test message to every channel that is on
curl -s -H "authorization: Bearer $TOKEN" https://dns1.isp.example/api/metrics | grep dnsone_health_status
```

### Moving zones in: import, export, reverse DNS

- **Import a zone** (*Zones → Import zone*): paste or upload a BIND zone file (cPanel and most panels
  export one), or transfer the zone from the current server (AXFR, optionally with TSIG; allow
  transfers to this server there first). *Preview* lists what would be created, what is skipped and
  why (unsupported types, DNSSEC records: DNSOne signs zones itself), and TTLs that were clamped.
  The old serial is kept, so secondaries and caches accept the next one.
- **Import into a zone** (*Zone → Import*): *merge* adds what the zone does not have, *replace* makes
  the zone match the file (preview first; it shows what would be deleted). The SOA settings stay.
- **Export** (*Zone → Zone file → Download*): the zone as BIND writes it, `GET /api/zones/{id}/export`.
- **Reverse DNS** (*Zone → Reverse DNS*, in `in-addr.arpa`/`ip6.arpa` zones): PTR records for a subnet
  from a pattern such as `pool-{a}-{b}-{c}-{d}.isp.example`, up to 65,536 addresses at a time; with
  *Also add the matching A/AAAA records*, the forward records are added in the hosted zone of each name,
  so mail servers see forward-confirmed reverse DNS. Existing records are kept unless *Replace* is on.

Record types: A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR, and since 1.2 DS (for delegations to signed
child zones), TLSA (DANE), SSHFP, NAPTR (VoIP/ENUM), HTTPS and SVCB.

### Verify step 7

- [ ] `systemctl list-timers 'dnsone-*'` shows the five timers with a next run
- [ ] Profile → two-factor sign-in on; signing in again asks for the code; a recovery code works once
- [ ] Settings → Backup: download; restore it on a test server; `dnsone-ctl status` is OK afterwards
- [ ] `/opt/dnsone/ops/dnsone-backup` writes a run, and `sha256sum -c SHA256SUMS` passes inside it
- [ ] `dnsone-status; echo $?` → `0`
- [ ] Stop the Recursor (`systemctl stop pdns-recursor`): `/api/health` → 503 and the dashboard shows it; start it again
- [ ] `logrotate -d /etc/logrotate.d/dnsone` shows no errors
- [ ] Settings → Alerts: *Save and send a test* reaches every channel that is on
- [ ] A test zone: *Sign this zone* → the DNSSEC tab shows a key and a DS record; `dig +dnssec` shows RRSIGs
- [ ] Zones → Import zone: a zone file from the old server previews and imports; its records resolve
- [ ] With encrypted DNS on: Android *Private DNS* set to the DoT name resolves; the *Encrypted DNS* check is ok

---

## Sizing and limits

- **50,000 clients**: dnsdist uses 4 listeners per address and the Recursor 4 threads with 2 M record
  cache and 1 M packet cache entries; raise `threads`/`LISTENERS_PER_ADDRESS` to the core count on
  bigger servers.
- **Rate limits** are per address (IPv4 /32, IPv6 /64): 200 qps (burst 400) by default, and
  5000 qps for NAT addresses (*Settings → DNS server*). Sustained floods get a 60-second dynamic block (REFUSED). List every
  CGNAT/NAT address, or busy NATs will be dropped.
- **Blocklists**: large lists (1–2 M names) take tens of seconds to build and about 0.5 GB of RAM
  while building; the Recursor holds the RPZ in memory (about 200 bytes per trigger), once per
  client group that uses the list.
- **Two-factor and app passwords**: local accounts only. If the last administrator loses their phone:
  `dnsone-ctl create-admin NAME --reset-two-factor` (also sets a new password).

## Single sign-on (Keycloak)

DNSOne 1.3 signs operators in through Keycloak (OpenID Connect, authorization code with PKCE),
installed on the same server by `ops/dnsone-upgrade-1.3`:

- Keycloak 26 with Ubuntu's Java 21, in `/opt/keycloak`, its own MySQL database `keycloak`, listening
  on `127.0.0.1:8180` only (`keycloak.service`, heap capped at 768 MB);
- nginx serves it at `https://<console>/auth/` with the console's certificate
  (`/etc/nginx/snippets/dnsone-keycloak.conf`), so no new name or certificate is needed;
- realm `pingomni`, client `dnsone` (confidential, PKCE required, exact redirect URI), roles
  `dnsone-admin`, `dnsone-operator`, `dnsone-viewer` (`ops/keycloak-realm`, safe to run again);
- `/etc/dnsone/dnsone.env`: `DNSONE_PUBLIC_URL`, `DNSONE_OIDC_ISSUER`, `DNSONE_OIDC_CLIENT_ID`,
  `DNSONE_OIDC_CLIENT_SECRET` (and optionally `DNSONE_OIDC_ROLES`, `DNSONE_OIDC_LABEL`).

```bash
bash /opt/dnsone/ops/dnsone-upgrade-1.3 /path/to/dnsone-src      # from 1.2; SSO_ADMIN=name to choose the first operator
cat /root/keycloak-credentials                                     # Keycloak admin and the first operator's temporary password
```

**Keycloak is the only way in.** The installer moves every local DNSOne account to Keycloak (same
username, email and role; the temporary passwords are in `/root/keycloak-credentials`) and switches
password sign-in off (`DNSONE_LOCAL_LOGIN=0`). The sign-in page then shows one button. DNSOne accounts
keep their id, history and app passwords (scripts and Prometheus keep working).

Everything day to day is in **Settings → Single sign-on** (DNSOne talks to Keycloak's admin API
as the `dnsone-admin-api` service account; nothing needs Keycloak's own console):

- **Operators**: create (generated temporary password, an email invitation, or a password you set),
  edit name, email and DNSOne role, require two-factor, new password or reset email, reset two-factor
  (lost phone), sign out everywhere, disable, delete. Disabling, deleting or signing out ends the
  operator's DNSOne sessions at once. Nobody can disable, demote or delete themselves.
- **Security**: two-factor required for everyone (existing operators set it up at their next sign-in),
  password rules (length, character classes, history, expiry, not the username), lockout after wrong
  passwords, inactivity and maximum session length, "remember me", "forgot password".
- **Sign-in options**: Google, Microsoft (Entra ID) or any OpenID Connect provider (the page shows the
  redirect URI to register there); Active Directory / LDAP (read-only, test, sync). People who arrive
  this way need a DNSOne role in *Operators* before DNSOne lets them in.
- **Events**: sign-ins, failures, sign-outs, password and two-factor changes (90 days).
- **Email**: the SMTP server Keycloak sends invitations and password resets with (with a test send).

Each operator manages their own password, two-factor and devices from *My profile → Open my account*
(Keycloak's account page). Anything else Keycloak can do is in its admin console, linked from the page.

**Emergency access** (Keycloak down or misconfigured): on the server,

```bash
dnsone-ctl sso emergency-login gnezha     # prints a one-time link, valid 10 minutes, audited
```

To go back to DNSOne passwords: `DNSONE_LOCAL_LOGIN=1` in `/etc/dnsone/dnsone.env` and restart
`dnsone-api` (moved accounts then need a new password: `dnsone-ctl create-admin NAME`). To turn SSO off
entirely, also remove `DNSONE_OIDC_ISSUER`.

The nightly `dnsone-backup` dumps the `keycloak` database too (`keycloak.sql.gz`) and keeps
`/etc/keycloak` and `/opt/keycloak/conf`.

```bash
systemctl status keycloak; journalctl -u keycloak -n 50
curl -s http://127.0.0.1:9000/auth/health/ready                   # {"status": "UP", ...}
curl -s https://<console>/api/auth/oidc                           # {"enabled": true, ...}
```

## Phase 2: clustering

Every DNSOne server shares one MySQL database. One node is the **primary** (it publishes zones);
the others are **replicas** (`DNSONE_ROLE=replica`), which resolve and block for customers and get
hosted zones from the primary by zone transfer. Each node builds its own RPZ and runtime files from
MySQL: `dnsone-sync.timer` (`dnsone-ctl sync`, every 30 s) applies changes made on any node, publishes
zones edited through a replica's console on the primary, downloads lists a node lacks, and records a
heartbeat. *Settings → Cluster* lists the nodes, whether each one's Recursor and dnsdist run the
current data, and the BIND secondaries.

1. **Shared MySQL**: a MySQL 8 server (or group replication) reachable from every node; point each
   node's `DNSONE_DATABASE_URL` at it and give each a distinct `DNSONE_NODE_NAME`. Sessions, audit,
   statistics, groups, rules and settings are all in MySQL; job locks are MySQL advisory locks per node.
2. **Primary BIND**: let it listen where the secondaries can reach it, e.g.
   `listen-on port 5301 { 127.0.0.1; 10.0.0.11; };` in `named.conf.options`, and open 5301/tcp+udp
   from the secondaries only (`ufw allow from 10.0.0.12 to any port 5301`). In *Settings → Cluster →
   BIND secondaries* list them (address, port 5301). The primary then serves a catalog zone
   (`catalog.dnsone`, RFC 9432) naming every hosted zone, notifies the secondaries and lets them
   transfer.
3. **Each replica**: install it like the primary (steps 1–2, without `dnsone-ctl migrate` or
   `create-admin`), with `DNSONE_ROLE=replica` in `dnsone.env`. Its BIND is a secondary that follows
   the catalog: `dnsone-ctl cluster secondary-config --primary 10.0.0.11` prints the lines for
   `named.conf.options` and `named.conf.local`. Zones then appear and disappear on the replica by
   themselves; its Recursor forwards hosted zones to its own BIND.
4. Put the nodes behind anycast or list them all as resolvers in the customers' DHCP/PPPoE settings.

```bash
dnsone-ctl cluster nodes                       # every node, its last sync, RPZ state
dig @10.0.0.12 -p 5301 catalog.dnsone SOA      # on a replica: the catalog serial matches the primary's
```
