# DNSOne user guide

Everything the console does, for the people who use it: operators, administrators, resellers and
customers. Installing and running the server is in [RUNBOOK.md](RUNBOOK.md).

Page names below are as they appear in the console's navigation: **Page → tab**. In the console, this
guide is under **Help**.

## Contents

1. [What DNSOne does](#1-what-dnsone-does)
2. [Signing in and your account](#2-signing-in-and-your-account)
3. [Who can do what](#3-who-can-do-what)
4. [Dashboard](#4-dashboard)
5. [Zones (authoritative DNS)](#5-zones-authoritative-dns)
6. [The resolver for your customers](#6-the-resolver-for-your-customers)
7. [Ad-blocking and client groups](#7-ad-blocking-and-client-groups)
8. [Court-ordered blocking](#8-court-ordered-blocking)
9. [Query log](#9-query-log)
10. [Protection (attacks)](#10-protection-attacks)
11. [Customers, resellers and quotas](#11-customers-resellers-and-quotas)
12. [Settings](#12-settings)
13. [Audit log](#13-audit-log)
14. [Automation: API, dynamic DNS, certbot](#14-automation-api-dynamic-dns-certbot)
15. [Good to know](#15-good-to-know)

---

## 1. What DNSOne does

DNSOne runs an ISP's DNS on one server (or a cluster):

- **Authoritative DNS**: the zones you host (your domains, your customers' domains, reverse DNS for
  your address space), answered by BIND to the whole internet.
- **A resolver for your customers**: they use this server as their DNS. It resolves everything from
  the root, validates DNSSEC, and can block ads, malware and court-ordered names, per group of
  customers.
- **Protection**: rate limits, attack detection and the server's firewall.

What happens behind the scenes, in short: every change you make in the console is stored in MySQL,
checked, and published to the DNS servers within seconds. If a change cannot be published (BIND
refuses it), the old version keeps being served and the console shows why.

```
customers ──53/853/443──▶ dnsdist ──▶ Recursor (cache, ad-blocking, groups) ──▶ internet
internet  ──53──────────▶ dnsdist ──▶ BIND (hosted zones only)
```

## 2. Signing in and your account

- **Sign in** with your username and password, or with *Sign in with …* if your organisation uses
  single sign-on (Google, Entra ID, Okta, any OpenID Connect provider).
- After 5 wrong passwords the account is locked for 15 minutes.
- Sessions last 12 hours of inactivity.

**My profile** (your name, top right):

- **Change password**: at least 12 characters. Changing it signs you out everywhere else.
- **Two-factor sign-in**: scan the code with an authenticator app (Google Authenticator, Authy,
  1Password…), then keep the **recovery codes** somewhere safe: each works once if you lose your
  phone. An administrator can also turn two-factor off for you.
- **App passwords**: for scripts and tools that call the API (see section 14). Each can be
  read-only and can expire. The secret is shown once.
- **Your limits**: if your account has quotas (section 11), they are shown under *Account*.

## 3. Who can do what

Every account has a **role**. Built-in roles:

| Role | Can |
|---|---|
| admin | everything, including users, roles, settings and the firewall |
| operator | zones, ad-blocking, groups, court orders (read), protection, query log, audit log |
| viewer | see zones, ad-blocking and statistics; change nothing |
| reseller | create zones and its own customer accounts; sees only its own zones and customers |
| customer | change the records of the zones given to it; nothing else |

Administrators can make **custom roles** in *Settings → Users → Roles*: any set of permissions, and
either "every zone" or "only the zones given to the user". Roles limited to their own zones can only
hold zone permissions.

The navigation only shows the pages your role can open.

## 4. Dashboard

- **Key figures**: queries, blocked share, cache hit rate and queries per second, over 24 hours.
- **Service health**: MySQL, BIND, the Recursor, dnsdist, publishing, ad-blocking, the query log,
  disk, the firewall. Anything not green says what is wrong.
- **Queries, last 24 hours**: per hour, with blocked queries.
- **Recent changes**: the last changes from the audit log.

## 5. Zones (authoritative DNS)

### Creating a zone

*Zones → New zone*: the name (`example.com`, or a reverse zone like `2.0.192.in-addr.arpa`), the
contact email, and the name servers. A name server inside the zone (`ns1.example.com`) needs its IP
address (glue). Optionally start from a **template** (below).

Or *Zones → Import*: from a BIND zone file, or by transferring it (AXFR) from the server that hosts
it now, with a TSIG key if needed. Choose *Preview* first: it shows what will be created and what is
skipped.

Remember to point the domain's NS records **at the registrar** to your name servers; DNSOne cannot
do that for you.

### Records

*Zone → Records*: add, edit, disable (kept but not published) or delete records. Names are relative
to the zone: `www`, `mail`, `@` for the zone itself.

Supported types: **A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR, DS, TLSA, SSHFP, NAPTR, HTTPS, SVCB**
and **ALIAS**.

- **ALIAS** is a CNAME that is allowed at the zone apex (`@ ALIAS myapp.cdn.example.`). DNSOne
  publishes the target's A/AAAA addresses and republishes within 5 minutes when they change.
- A CNAME must be alone at its name; DNSOne refuses combinations BIND would reject.
- TXT values can be long (SPF, DKIM): DNSOne splits them correctly.
- TTL empty = the zone's default TTL.

### Publishing

Every change is published within seconds. The zone's badge shows:

| State | Meaning |
|---|---|
| published | BIND serves exactly what you see |
| publishing / pending | a change is on its way (a few seconds) |
| publish failed | BIND refused the change; **the previous version is still served**. The red box says why. Fix it and the next change publishes, or use *Publish now* |

Each publish raises the SOA serial (`YYYYMMDDnn`).

### Zone settings, zone file

- *SOA and settings*: default TTL, primary name server, contact, refresh/retry/expire, negative
  cache TTL.
- *Zone file*: the exact file BIND loads, as a read-only preview, and *Download*.
- *Disable zone*: BIND stops answering for it; records are kept. *Delete zone* removes it for good.

### History and rollback

*Zone → History*: every publish that changed the zone (the last 100), with what changed and who
changed it. *Show* any version, then *Roll back to this version*: the zone's records and SOA settings
become that version's again, as a new change (which is itself in the history, so it can be undone).

### Templates

*Zone templates*: a set of records (and name servers, contact, TTL) with variables like `{ip}`,
`{zone}`. Use one when creating a zone, or *Zone → Template* to add its records to an existing zone.
Records that already exist or conflict are skipped and listed.

### Reverse DNS for a whole subnet

In a reverse zone, *Zone → Reverse DNS*: give a subnet (e.g. a customer pool `198.51.100.0/24`) and a
name pattern (e.g. `host-{a}-{b}-{c}-{d}.dyn.isp.example.`). DNSOne creates every PTR record, and
optionally the matching A/AAAA records in your forward zone. Preview first.

### Dynamic DNS

For routers, home servers and certbot. An administrator turns it on in *Settings → DNS server*; then
*Zone → Dynamic DNS → New key*: which names (`home`, `*.dyn`, `_acme-challenge`) and which record
types the key may change. The secret is shown once, with ready-made settings for nsupdate, routers
(dyndns2) and certbot. Every update is checked, audited and kept in the zone's history.

### Zone transfers to secondaries (new in 1.5)

*Zone → Transfers*: let other name servers (for example a customer's own) keep a copy of the zone.

- *Allow a secondary*: its address (notified when the zone changes) or a network (allowed to
  transfer, not notified). Up to 20 entries.
- *Require a key*: transfers must also be signed with a TSIG key. The dialog shows the configuration
  for a BIND secondary. Make a new key at any time; secondaries using the old one stop receiving
  updates until they get it.
- The secondary transfers from this server's DNS address, port 53.
- **Every other transfer is refused.** (Before 1.4.5 anyone could copy any hosted zone.)

### DNSSEC

*Zone → DNSSEC → Sign this zone*: BIND creates a key and signs the zone. Then:

1. Give the **DS record** shown to your registrar (some ask for the DNSKEY instead, also shown).
   Registries that read **CDS** records take it from the zone by themselves (the tab shows the CDS
   once BIND publishes it; with the default timings that is about a week after signing).
2. DNSOne checks the parent every 5 minutes (or *Check the parent now*). When the DS is there, the
   tab says **"signed and secure"**.

If the **parent zone is hosted here too** (e.g. `customer.isp.example` under `isp.example`, with NS
records for it in the parent), you do nothing: DNSOne puts the DS records in the parent by itself.

- **Roll the key**: replaces the signing key safely. The new key's DS must reach the parent (by
  itself with a hosted parent or a CDS-reading registry, otherwise give the new DS to the registrar
  when the tab shows it). The old key goes after BIND has re-signed the zone (days). You can't start
  a second rollover before the first has finished.
- **Stop signing**: remove the DS at the registrar first and wait a day (DNSOne refuses otherwise,
  because validating resolvers would fail the zone). With a hosted parent DNSOne removes it for you.
- Signed zones accept TTLs up to the server's limit (a week by default); a longer one is refused with
  a clear message.

## 6. The resolver for your customers

Customers whose addresses are in *Settings → DNS server → Customer networks* may use this server as
their resolver; everyone else only gets answers for the zones hosted here.

- **DNSSEC validation** is always on: forged or broken answers become SERVFAIL. Your own hosted zones
  are exempt (they resolve for customers even before they are delegated).
- **Rate limits**: per customer address (or IPv6 /64), with a higher limit for **NAT addresses**
  (CGNAT gateways that carry many homes). Queries above the limit are dropped.
- **Encrypted DNS** (if your server has a certificate): DNS over TLS on port 853 (Android "Private
  DNS": enter the server's name) and DNS over HTTPS at `https://<name>/dns-query`.
- **Serve-stale** (new in 1.5): when a site's name servers are down, customers keep getting its last
  answer for up to 12 hours (*Settings → DNS server → Resolver*).
- **EDNS Client Subnet** (new in 1.5, off by default): for the CDN domains you list, the customer's
  /24 is passed on so the CDN answers with a nearby server. Never sent for private or CGNAT
  addresses, and never to domains you did not list.

## 7. Ad-blocking and client groups

### Ad-blocking

*Ad-blocking*:

- **Blocklists and allowlists**: subscribe to lists by URL (hosts files, plain domain lists, Adblock
  syntax). They are downloaded every 6 hours. Allowlists win over blocklists.
- **Rules**: block or allow one domain (and, by default, everything below it), or a **regex**. A rule
  can apply to everyone or to one client group. *Import* adds up to 50,000 domains at once.
- **Policy**: what a blocked name answers: "does not exist" (NXDOMAIN, default), "no data", a null IP
  (0.0.0.0 / ::), or a redirect to your own page (walled garden).
- **Check a domain**: is it blocked, for which group, and by which list or rule?
- **Pause blocking** for everyone or for one group, for N minutes or until resumed.

Changes reach customers within about a minute (blocked answers are cached for at most 60 seconds).

### Client groups

*Client groups*: different rules for different customers, e.g. *Family*, *Business (no blocking)*.

- Add networks or single addresses to a group. A customer belongs to the group of its **most
  specific** network; everyone else is in *Default*.
- Per group: ad-blocking on or off, its own lists and rules, and:
  - **Safe Search**: Google, Bing and DuckDuckGo always filter explicit results (stays on while
    blocking is paused);
  - **YouTube**: restricted mode, moderate or strict;
  - **DNS64**: IPv6-only customers reach IPv4-only sites (needs a NAT64 gateway).
- *Which group is a client in?* answers for any address.

## 8. Court-ordered blocking

*Court orders*: names a court or regulator ordered blocked. Separate from ad-blocking on purpose:

- They apply to **every customer and every group**, ahead of allow rules, allowlists and pauses.
- `example.com` blocks the name and everything below it; `*.example.com` only what is below it.
- Each entry records the authority, the order's reference and date, and who added it.
- Entries are never deleted: *Lift* (one name, or a whole order) with a reason; the list keeps the
  history. *Export CSV* is the record for the regulator.
- Blocked names answer with the **legal notice page** (HTTP 451) if one is set up, otherwise "does
  not exist", with the DNS extended error "Censored".

## 9. Query log

*Query log* (if your server keeps one): who asked for what, and what they got.

- Search and filter by client, domain, type, reply and verdict (ok, blocked, allowed by a rule,
  court order); click a client or name to see only that. *Live* shows queries as they arrive.
- **Allow / block this domain** directly from a row.
- **Top lists**: permitted and blocked domains, clients, clients with the most blocked queries,
  query types and reply codes, for a chosen period; **History**: per day, 30 days.
- **Privacy** (*Settings → Privacy*): keep everything, hide domains, hide domains and clients, or
  only totals; and how long queries are kept. *Erase now* deletes the log (and optionally the
  statistics).
- **Export** (*Settings → Query log export*): send every answer (or only blocked ones) to your SIEM
  by syslog, or the raw DNS messages by dnstap.

## 10. Protection (attacks)

*Protection* (new in 1.5) shows what dnsdist is blocking by itself and why:

| Kind | What it is | What happens |
|---|---|---|
| Random-subdomain attack | a domain asked for with thousands of names that do not exist ("water torture"), to overload its name servers | refused for everyone for a few minutes; never your hosted zones |
| Infected client (off by default) | a customer whose answers are mostly "does not exist" | its queries are dropped for a while |
| Amplification | a customer receiving far more data than a real user (its address is being spoofed) | answers are truncated, so real clients retry over TCP and spoofed ones get nothing |
| Query / SERVFAIL flood | a customer far above its query rate | refused for a minute |

- **Blocked now**, the **last 24 hours** by kind, the **most blocked** targets, and a week of
  **history**.
- **Block a client or domain** yourself, for an hour, a day, a week or until removed: a client's
  queries are dropped, a domain is refused, on every node. Administrators can block a client **at
  the firewall** instead (all traffic, not only DNS).
- **Thresholds** can be changed. The "infected client" rule is off by default because ad-blocked names
  also answer "does not exist": turn it on with a threshold above what a busy household sends.
- NAT addresses and the server itself are never blocked automatically.

## 11. Customers, resellers and quotas

- **Resellers** create zones (which become theirs) and **customer accounts** under *Customers*. They
  can give their customers only their own zones, and see only their own customers.
- **Customers** see only the zones given to them, and change their records, dynamic DNS keys and
  transfers. They can't create or delete zones unless their role allows it.
- **Quotas** (new in 1.5), in the user dialog, for accounts limited to their own zones:
  - **zones it may hold**;
  - **records per zone**, checked when the account adds records (an administrator adding records to
    the customer's zone is not limited);
  - **API requests per minute**, console and app passwords together. Above it the API answers
    "429 Too many requests" with a `Retry-After`.

  Empty means no limit. A reseller's customers can't get more than the reseller has, and inherit the
  reseller's limits when left empty.

## 12. Settings

Administrators only, except where noted.

| Tab | What you set |
|---|---|
| **Overview** | system information, shortcuts, and **Software update**: see if a new DNSOne release exists and install it with one click (the console restarts by itself) |
| **Users** | accounts, roles, the zones of customers and resellers, quotas, resetting two-factor |
| **DNS server** | customer networks, NAT addresses, rate limits, public authoritative DNS on/off, DNS64 prefix, dynamic DNS on/off; **Resolver**: serve-stale and ECS (saving restarts the resolver; its cache starts empty) |
| **Privacy** | what the query log keeps, and for how long; erase |
| **Alerts** | email, webhook (Slack, Teams, Mattermost…) or Telegram when something breaks: a service, publishing, a blocklist, a certificate, a cluster node, a query flood. Plus the Prometheus metrics address |
| **Query log export** | syslog to a SIEM, dnstap |
| **Single sign-on** | an OpenID Connect provider, role mapping from a group claim, allowed email domains |
| **Backup** | download zones, ad-blocking, settings and court orders as one file, and restore any of them |
| **Cluster** | the nodes sharing this database and their sync state; BIND secondaries for the hosted zones |
| **Firewall** | the server's firewall, see below |

### Firewall (new in 1.5)

DNSOne can manage the server's firewall. Off until you turn it on.

1. **Management networks**: where you administer from. SSH and the console (ports 22, 80, 443) are
   always open to them, **whatever the rules say**, so you cannot lock yourself out with a rule.
   The page shows your current address; it must be inside.
2. **Open to everyone**: DNS (53), DNS over TLS (853), DNS over HTTPS (443).
3. **Rules**, checked in order: accept, drop or reject by source, protocol and ports (e.g. *accept TCP
   3306 from the replica*, *drop everything from 192.0.2.0/24*). A rule can be temporary.
4. Everything else is dropped. The server's own connections, loopback and essential ICMP always work.

Edits are a **draft** until you click **Apply**. Then:

- the server applies the rules, and **this page confirms it can still reach the server**. Keep the
  page open for those seconds;
- if it can't confirm within a minute (you locked yourself out), **the previous rules come back by
  themselves**;
- the other nodes of a cluster pick up the rules within a minute.

The preview shows the exact nftables rules. If the server also uses ufw, turn ufw off once DNSOne's
firewall works (with both, traffic must pass both). The firewall is not in backups: its rules belong
to one server.

## 13. Audit log

*Audit log*: every change anyone made (zones, records, rules, users, settings, sign-ins), with who,
when, from which address, and what exactly changed. Filter by person, action or item.

## 14. Automation: API, dynamic DNS, certbot

- **API**: everything the console does is in the API, documented at `https://<console>/api/docs`.
  Use an **app password** (*My profile*): `Authorization: Bearer dno_…`. Read-only app passwords can
  only read. App passwords have the same reach as their account (a customer's only its zones).

  ```bash
  curl -H "Authorization: Bearer dno_..." https://dns.isp.example/api/zones
  ```
- **Dynamic DNS for routers** (dyndns2, "custom" provider in most routers): server = the console's
  name, path `/nic/update`, username = the key's first label, password = the key's secret.
- **nsupdate** (RFC 2136):

  ```bash
  nsupdate -y hmac-sha256:router.example.com.:SECRET <<'END'
  server 203.0.113.53
  zone example.com.
  update delete home.example.com. A
  update add home.example.com. 300 A 198.51.100.7
  send
  END
  ```
- **certbot** wildcard certificates: the `dns-rfc2136` plugin with a dynamic DNS key allowed to change
  `_acme-challenge` TXT records.
- **Prometheus**: `/api/metrics` (see *Settings → Alerts*).

## 15. Good to know

- **Changes are live in seconds**: zones within a few seconds, ad-blocking within a minute, DNS
  server settings within 2 seconds. Resolvers elsewhere on the internet may still have the old answer
  cached until its TTL runs out: lower a record's TTL a day before a planned change.
- **A failed publish never breaks a zone**: the previous version keeps being served.
- **Customers see hosted zones immediately**, even before the domain is delegated at the registrar.
- **NXDOMAIN for blocked names**: if customers report a site "does not exist", check it in
  *Ad-blocking → Check a domain*, or look it up in the query log.
- **Pausing** ad-blocking does not pause court orders or Safe Search.
- **Two-factor**: keep your recovery codes; without them and your phone, an administrator must turn
  it off for you.
- **Software updates** keep DNS answering; a new minor version (1.4 → 1.5) restarts dnsdist (a second
  or two) and may restart the resolver (its cache starts empty). Updates roll back by themselves if
  they fail.
- **Backups**: the server backs itself up every night. *Settings → Backup* is for moving settings
  between servers or keeping your own copy.
- **Where to get help**: the red messages in the console say what to fix; the audit log says who
  changed what; administrators find everything else in [RUNBOOK.md](RUNBOOK.md).
