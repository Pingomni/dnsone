# DNSOne roadmap

Features after Phase 1, mostly the gaps found by comparing DNSOne with Pi-hole (October 2026),
in priority order for an ISP. All of them, and Phase 2 (clustering, end of RUNBOOK.md), shipped in
DNSOne 1.1 (October 2026), with end-to-end tests against real MySQL, BIND, Recursor and dnsdist
(`backend/tests/test_features.py`).

| # | Feature | Status |
|---|---|---|
| 1 | **Query visibility**: query log (who asked what, blocked or not) with search and filters; top domains, top blocked domains and top clients; query types and reply codes; live view; per-client view; "allow / block this domain" from the log; history over weeks | done |
| 2 | **Per-client policies (groups)**: assign client IPs / subnets to groups, each with its own blocklists and allow/deny rules (e.g. no ad-blocking, family filter, business customer) | done |
| 3 | **More rule types**: regex block/allow rules; allowlist subscriptions (downloaded allowlists) | done |
| 4 | **Blocking controls**: pause blocking for N minutes (per group or everyone); "null IP" block answer (0.0.0.0 / ::) | done |
| 5 | **Two-factor sign-in** (TOTP, as in RadiusOne) and app passwords for API access | done |
| 6 | **Settings → DNS server**: client networks, NAT addresses and rate limits edited in the console instead of dnsdist.conf | done |
| 7 | **Settings → Backup / Teleporter**: download and restore settings, lists and rules from the console | done |
| 8 | **Privacy levels** for the query log: hide clients and/or domains, shorter retention | done |
| 9 | **Phase 2: clustering**: shared MySQL, replica nodes, BIND secondaries through a catalog zone, node sync and health | done |

## DNSOne 1.2 (October 2026)

The gaps found by comparing DNSOne 1.1 with what ISPs expect of a DNS platform, highest value first.
All shipped in 1.2, with end-to-end tests (`backend/tests/test_zone_tools.py`, `test_ops.py`).

| # | Feature | Status |
|---|---|---|
| 10 | **DNSSEC signing** of hosted zones (BIND inline signing, one ECDSA P-256 key, DS records for the registrar, safe unsigning) | done |
| 11 | **More record types**: DS, TLSA, SSHFP, NAPTR, HTTPS, SVCB | done |
| 12 | **Zone import and export**: BIND zone files and AXFR (with TSIG), merge or replace, preview | done |
| 13 | **Bulk reverse DNS**: PTR records for a subnet from a pattern, with matching forward records | done |
| 14 | **Encrypted DNS**: DoT and DoH listeners in dnsdist, certificate expiry check, certbot hook | done |
| 15 | **Alerts** (email, webhook, Telegram) and **Prometheus metrics** (`/api/metrics`) | done |

## DNSOne 1.3.1 (October 2026)

DNSOne's own colour (teal) in the console, logo and favicon. Single sign-on with Keycloak was built in
1.3 and removed again in 1.3.1: with one portal and a few operators, DNSOne's own sign-in (Argon2id
passwords, two-factor, lockout, app passwords) covers what is needed with one interface.

## DNSOne 1.4 (October 2026)

What ISPs asked for next, all with end-to-end tests (`backend/tests/test_isp.py`) and
`ops/dnsone-upgrade-1.4` (from 1.3.1, with rollback).

| # | Feature | Status |
|---|---|---|
| 16 | **Court-ordered blocking**: its own audited list (entries are lifted with a reason, never deleted), for every client and group, not undone by allow rules or pauses; legal notice page (HTTP 451) or NXDOMAIN, Extended DNS Error 16; CSV export | done |
| 17 | **Custom roles and per-zone permissions**: roles limited to their own zones; built-in *reseller* (creates zones and its own customers) and *customer* (edits the records of its zones) | done |
| 18 | **Single sign-on** with any OpenID Connect provider (PKCE, signed ID tokens, role mapping from a claim, invitations by email); no identity server to install | done |
| 19 | **Zone history and rollback**: a version per publish that changed the zone, with the difference and who made it | done |
| 20 | **Safe Search** (Google, Bing, DuckDuckGo) and YouTube restricted mode per client group, kept while blocking is paused | done |
| 21 | **Query log export**: syslog (RFC 5424, JSON or key=value, UDP/TCP) with the verdict and group; dnstap from dnsdist | done |
| 22 | **Zone templates** with variables, for new zones and existing ones | done |
| 23 | **Dynamic DNS**: RFC 2136 updates signed with TSIG keys limited to names and types (routers, certbot DNS-01), and dyndns2 (`/nic/update`); MySQL stays the source of truth | done |
| 24 | **DNS64** per client group, with PTR answers for synthesised addresses | done |
| 25 | **ALIAS records**, at the apex too: flattened to A/AAAA at publish time and refreshed when the target moves | done |

## DNSOne 1.5 (October 2026)

What came next for ISPs, with end-to-end tests (`backend/tests/test_v15.py`) and
`ops/dnsone-upgrade-1.5` (from 1.4, with rollback).

| # | Feature | Status |
|---|---|---|
| 26 | **Zone transfers to customers' own secondaries**: per-zone addresses and TSIG key, NOTIFY; every other transfer through port 53 refused (1.4 let anyone transfer hosted zones) | done |
| 27 | **Customer quotas**: zones, records per zone, API requests per minute; resellers' customers within the reseller's own | done |
| 28 | **EDNS Client Subnet** for listed (CDN) domains, never for private or CGNAT addresses | done |
| 29 | **DNSSEC automation**: CDS/CDNSKEY, BIND told when the parent's DS changes, hosted parents kept in step, key rollovers | done |
| 30 | **Serve-stale** (RFC 8767) in the Recursor | done |
| 31 | **Attack protection**: random-subdomain, infected-client and amplification detection in dnsdist, history, manual blocks | done |
| 32 | **Firewall** (nftables) managed from the console, with management networks that cannot be locked out and a confirm-or-roll-back apply | done |

Next candidates: tests in CI (the unit tests on every push, the end-to-end tests in containers),
anycast with health-checked BGP announcements, threat-intelligence categories per client group.

Not planned (home-network features without a place in an ISP resolver): DHCP server, network device
list, choosing upstream resolvers (DNSOne resolves from the root).
