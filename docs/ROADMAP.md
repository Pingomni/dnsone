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

Next candidates: single sign-on (Keycloak/OIDC, schema ready), custom roles and per-zone permissions
(customer or reseller self-service), a separate, audited list for court-ordered blocking with a
legal-notice block page, Safe Search enforcement per group, query log export (syslog/dnstap),
zone change history with rollback, zone templates, dynamic DNS (TSIG updates), DNS64, ALIAS/ANAME
records at the apex (BIND has no native support: it needs flattening at publish time).

Not planned (home-network features without a place in an ISP resolver): DHCP server, network device
list, choosing upstream resolvers (DNSOne resolves from the root).
