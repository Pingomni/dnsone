# DNSOne

**[Website](https://pingomni.com/dnsone/)** · **[Live demo](https://demo-dns.pingomni.com/)** (demo / demo) · **[User guide](https://pingomni.com/docs/dnsone/)** · by [PingOmni](https://pingomni.com/)

DNS management for ISPs: authoritative zones (cPanel-style, on BIND), a caching resolver (PowerDNS
Recursor) with RPZ ad-blocking, and dnsdist in front for ACLs and rate limiting. MySQL 8 is the
source of truth; a FastAPI backend generates and validates every file the DNS daemons load. The
operator console is a React SPA built on RadiusOne's theme and components.

Phase 1 is a complete single-server deployment for about 10,000 clients, sized for 50,000. Version
1.1 adds what an ISP needs beyond it: a query log with top lists and history, client groups with
their own lists and rules, regex rules and allowlists, paused blocking, a null-IP answer, two-factor
sign-in and app passwords, DNS server settings and backup/restore in the console, query log privacy
levels, and clustering (shared MySQL, replicas, BIND secondaries through a catalog zone). Version
1.2 adds DNSSEC signing of hosted zones, DS/TLSA/SSHFP/NAPTR/HTTPS/SVCB records, zone import (zone
file or AXFR) and export, bulk reverse DNS for address pools, DNS over TLS and HTTPS, alerts by email,
webhook or Telegram, and Prometheus metrics. Version 1.3.1 gives the console DNSOne's own colour.
Version 1.4 adds customer and reseller self-service (custom roles, per-zone permissions), zone
templates, zone history with rollback, ALIAS records at the apex, an audited court-ordered blocking
list with a legal notice page, Safe Search and YouTube restrictions per client group, DNS64, query log
export (syslog, dnstap), dynamic DNS (RFC 2136 with TSIG, and dyndns2 for routers) and single sign-on
with any OpenID Connect provider. Version 1.5 adds zone transfers to customers' own secondaries,
customer quotas, EDNS Client Subnet and serve-stale, DNSSEC automation (CDS, hosted parents, key
rollovers), attack protection in dnsdist, and the server's firewall managed from the console.

- **Use the console:** [docs/USER-GUIDE.md](docs/USER-GUIDE.md) (every feature, for operators, resellers and customers)
- **Install and operate:** [docs/RUNBOOK.md](docs/RUNBOOK.md) (every step, with commands and checks)
- **Schema:** [backend/migrations/0001_initial.sql](backend/migrations/0001_initial.sql)
- **API:** `/api/docs` on a running server (OpenAPI)

## Install

On a fresh **Ubuntu 24.04 LTS** server (2 GB RAM, 4 GB free disk), as root:

```bash
curl -fsSL https://raw.githubusercontent.com/Pingomni/dnsone/main/install.sh -o install.sh
sudo bash install.sh
```

It asks for the DNS address, the console address and host name, and the management network (each with a
suggestion from the server), installs the latest release with BIND, the Recursor, dnsdist, MySQL and nginx, and
prints the console URL with the first administrator's password. `bash install.sh --help` lists the options
(`--yes` for no questions, `--ufw` for a firewall). The [runbook](docs/RUNBOOK.md) has every step it does, by hand.

## Editions and licences

DNSOne is free and open source under the **GNU AGPL-3.0** ([LICENSE](LICENSE)): hosted zones, the customer resolver,
ad-blocking, client groups, the query log and everything around them. **DNSOne Pro** is in the same code, and turns
on with a licence key under *Settings → License*: attack protection, the firewall, zone transfers to customers'
secondaries, quotas and resellers, court-ordered blocking, single sign-on, query log export and clustering. Its files
are under the **Elastic License 2.0** ([LICENSE-PRO](LICENSE-PRO)): you may read and test them, but using them needs a
licence, and the licence check may not be removed. Licences, installation and support:
[pingomni.com/dnsone](https://pingomni.com/dnsone/), hello@pingomni.com.

A licence is for one server, or for a cluster: it is issued for the server ID shown under *Settings → License*
(for a cluster, any one of its servers) and says how many servers it covers. An expired licence never changes what DNS answers: the Pro features keep running as they were and can be changed
again once it is renewed. PingOmni issues keys with `tools/issue-license.py` (its signing key is not in this repository).
With a key installed, the server registers with your PingOmni account (account.pingomni.com) and checks in twice a
day, so you see which server each licence runs on; after a renewal it picks up the new key by itself. It sends the
key, a hash of `/etc/machine-id` and the host name. This is report only: the Pro features never depend on it, and
`DNSONE_ACCOUNT_URL=` (empty, in `/etc/dnsone/dnsone.env`) turns it off.

## Layout

```
backend/dnsone/        FastAPI app
  api/                 routers: auth (+ two-factor, app passwords), zones + records, rpz + lists, groups,
                       queries, users, settings (DNS server, privacy, backup), cluster, system
  validation.py        DNS name and record rules (match named-checkzone -k fail), networks, regexes
  zonegen.py           MySQL → zone files → named-checkzone → atomic rename → rndc, with rollback;
                       catalog zone for secondaries; replica mode; DNSSEC signing policy
  zoneio.py dnssec.py  zone import (file, AXFR), bulk reverse DNS; DNSSEC status and DS records
  alerts.py metrics.py alerts (email, webhook, Telegram); Prometheus /api/metrics
  transfers.py quota.py   zone transfers to customers' secondaries; customer quotas
  protection.py firewall.py   attack protection (dnsdist dynamic blocks); the nftables firewall and its root applier
  rpz.py               lists and rules → an allow and a block RPZ per client group → rec_control
  runtime.py           files dnsdist and the Recursor's policy script read: groups, pauses, regexes, ACL
  querylog.py pbdns.py dnsone-querylog: the Recursor's protobuf stream → query log and top lists
  privacy.py backup.py cluster.py   query log privacy levels; backup/restore; node sync and heartbeat
  stats.py health.py   dnsdist / Recursor metrics, component probes
  security.py audit.py Argon2id + MySQL sessions + CSRF, TOTP, app passwords; audit trail
  cli.py               dnsone-ctl (migrate, create-admin, status, sync, zones, rpz, stats, alerts, cluster)
backend/migrations/    SQL migrations (MySQL 8, InnoDB, utf8mb4)
backend/tests/         unit tests, and end-to-end tests against real MySQL/BIND/Recursor/dnsdist
frontend/src/          React SPA: RadiusOne's app.css, components and lib (unchanged, see
                       tools/sync-radiusone.sh); shim/ (Inertia stand-in); layouts/, pages/, dnsone.css
deploy/                bind/, recursor/ (incl. the dnsone.lua policy script), dnsdist/, systemd/, nginx/,
                       sudoers/, logrotate/, env/, ufw.sh
ops/                   dnsone-backup, dnsone-status, dnsone-ctl wrapper, dnsone-update, dnsone-firewall, upgrades
```

## Development

```bash
cd backend && python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest tests/test_validation.py           # unit tests, no services needed
# End-to-end: an env file pointing at a test MySQL and test BIND/Recursor/dnsdist instances.
DNSONE_TEST_ENV=/path/to/test.env DNSONE_TEST_DNSDIST=127.0.0.1:15353 .venv/bin/python -m pytest
# Clustering test: also a BIND secondary following the catalog zone (docs/RUNBOOK.md, Phase 2).
DNSONE_TEST_SECONDARY=127.0.0.1:25301 ...
# Encrypted DNS: dnsdist.conf with ENCRYPTED_DNS = true, then
DNSONE_TEST_DOT=127.0.0.1:853 DNSONE_TEST_DOH=https://127.0.0.1/dns-query ...

cd frontend && npm ci && npm run dev      # Vite on :5173, proxies /api to 127.0.0.1:8100
npm run build                             # type-check + frontend/dist
npm run sync-radiusone                    # refresh RadiusOne's shared UI files
```
