# DNSOne user guide

Everything the console does, for the people who use it: operators, administrators, resellers and
customers, with every field explained and examples to copy, plus the server commands. Installing and running
the server by hand is in [RUNBOOK.md](RUNBOOK.md).

Parts marked **(Pro)** need a DNSOne Pro licence (*Settings → License*); without one, DNSOne runs as DNSOne
Community and those pages are not shown. Page names below are as they appear in the console's navigation:
**Page → tab**. In the console, this guide is under **Help**. Examples use documentation addresses
(192.0.2.x, 198.51.100.x, 203.0.113.x, 2001:db8::) and names (example.com, isp.example).

## Contents

1. [What DNSOne does](#1-what-dnsone-does)
2. [Signing in and your account](#2-signing-in-and-your-account)
3. [Who can do what](#3-who-can-do-what)
4. [Dashboard](#4-dashboard)
5. [Zones (authoritative DNS)](#5-zones-authoritative-dns)
6. [The resolver for your customers](#6-the-resolver-for-your-customers)
7. [Ad-blocking and client groups](#7-ad-blocking-and-client-groups)
8. [Court-ordered blocking (Pro)](#8-court-ordered-blocking-pro)
9. [Query log](#9-query-log)
10. [Protection (attacks) (Pro)](#10-protection-attacks-pro)
11. [Customers, resellers and quotas (Pro)](#11-customers-resellers-and-quotas-pro)
12. [Settings](#12-settings)
13. [Audit log](#13-audit-log)
14. [Automation: API, dynamic DNS, certbot](#14-automation-api-dynamic-dns-certbot)
15. [Installing and updating](#15-installing-and-updating)
16. [Command reference](#16-command-reference)
17. [Good to know](#17-good-to-know)

---

## 1. What DNSOne does

DNSOne runs an ISP's DNS on one server (or a cluster):

- **Authoritative DNS**: the zones you host (your domains, your customers' domains, reverse DNS for
  your address space), answered by BIND to the whole internet.
- **A resolver for your customers**: they use this server as their DNS. It resolves everything from
  the root, validates DNSSEC, and can block ads, malware and court-ordered names, per group of
  customers.
- **Rate limits** per customer address, higher for NAT addresses.
- **Protection** (Pro): attack detection and the server's firewall.

What happens behind the scenes, in short: every change you make in the console is stored in MySQL,
checked, and published to the DNS servers within seconds. If a change cannot be published (BIND
refuses it), the old version keeps being served and the console shows why.

```
customers ──53/853/443──▶ dnsdist ──▶ Recursor (cache, ad-blocking, groups) ──▶ internet
internet  ──53──────────▶ dnsdist ──▶ BIND (hosted zones only)
```

| Part | Listens on | Does |
| --- | --- | --- |
| dnsdist | UDP/TCP 53, 853 (DoT), 443 `/dns-query` (DoH) | The front door: who may ask what, rate limits, attack protection, sends each query to the Recursor or BIND. |
| PowerDNS Recursor | 127.0.0.1:5300 | Resolves for customers, caches, validates DNSSEC, applies ad-blocking (RPZ) and client groups. |
| BIND | 127.0.0.1:5301 | Serves the zones hosted here, signs DNSSEC zones, sends zone transfers. |
| MySQL | 127.0.0.1:3306 | Everything you set in the console. |
| The console (nginx + API) | HTTPS 443 on the management address | The pages in this guide, and the API. |
| Timers | | Publishing, blocklist downloads, statistics, alerts, backups. |

### A first hour, step by step

1. Sign in with the administrator the installer printed, then **My profile → Two-factor sign-in**.
2. **Settings → DNS server**: check **Customer networks** (your customers' address ranges, e.g.
   `100.64.0.0/10`, `198.51.100.0/22`) and **NAT addresses** (your CGNAT gateways).
3. Point a test computer's DNS at the server and browse: the **Dashboard** starts counting.
4. **Ad-blocking**: add a blocklist, e.g. `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`.
5. **Zones → New zone**: host your first domain, then delegate it at the registrar.
6. **Settings → Alerts**: an email or Telegram for problems.
7. Give customers the server as DNS: in PPPoE or DHCP, DNS 1 = this server (DNS 2 = a second DNSOne in a
   cluster, or another resolver).

## 2. Signing in and your account

- **Sign in** with your username and password.
- **Single sign-on** (Pro): *Sign in with …* if your organisation uses Google, Entra ID, Okta or any
  OpenID Connect provider.
- After 5 wrong passwords the account is locked for 15 minutes.
- Sessions last 12 hours of inactivity.

**My profile** (your name, top right):

| Part | What it does |
| --- | --- |
| Account | Your username, name, email, role and how you sign in (DNSOne password or single sign-on). |
| Change password | Current password, then the new one twice (at least 12 characters). Changing it signs you out everywhere else. |
| Two-factor sign-in | Scan the code with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, FreeOTP…) or type the key by hand, then enter the **Code from the app**. Keep the **recovery codes** somewhere safe: each works once if you lose your phone. To turn it off, enter a current code. An administrator can also turn it off for you. |
| App passwords | For scripts and monitoring that call the API (see [Automation](#14-automation-api-dynamic-dns-certbot)). Give it a **Name** (e.g. `monitoring`), tick **Read-only** if it only needs to read, and optionally an **Expires** date. The secret (`dno_…`) is shown once. **Revoke** stops it at once. The list shows when each was last used. |
| Your limits (Pro) | If your account has quotas ([section 11](#11-customers-resellers-and-quotas-pro)), they are shown here with what you use. |

## 3. Who can do what

Every account has a **role**. Built-in roles:

| Role | Can |
|---|---|
| admin | everything, including users, roles, settings and the firewall |
| operator | zones, ad-blocking, groups, court orders (read), protection, query log, audit log |
| viewer | see zones, ad-blocking and statistics; change nothing |
| reseller (Pro) | create zones and its own customer accounts; sees only its own zones and customers |
| customer | change the records of the zones given to it; nothing else |

Administrators can make **custom roles** in *Settings → Users → Roles*: a name, a description, any set of
permissions, and either **Every zone** or **Only the zones given to the user** (customers, resellers). Roles
limited to their own zones can only hold zone permissions. Built-in roles keep their permissions; create a new
role for different access.

**Example: a support role.** Name `support`, permissions *zones: read*, *query log: read*, *ad-blocking: read*,
**Every zone**. Support staff can then look up a customer's records and queries but change nothing.

The navigation only shows the pages your role can open.

## 4. Dashboard

- **Key figures**: queries, blocked share, cache hit rate and queries per second, over 24 hours.
- **Service health**, under the key figures: one line that says whether every check passes or names the
  ones that do not, then each check in its group (DNS service, DNSOne, Server) with ✓, ! (warning) or ×
  (problem). A check that fails shows what is wrong under its name. It refreshes every 30 seconds.
- **Queries over the last 24 hours**: answered and blocked queries every 10 minutes. Point at the chart
  (or tap it) for the numbers at that moment; *Show as a table* lists them all.
- **Clients over the last 24 hours**: queries per hour from the seven busiest clients, the rest as *Other*.
- **Query types**, **Replies** (NOERROR, NXDOMAIN, SERVFAIL…) and **Answers** (answered, blocked,
  allowed by a rule, court order): shares of the last 24 hours, with counts and percentages.
- **Top domains**, **Top blocked domains** and **Top clients**: click one to open the query log for it.
- **Recent changes**: the last changes from the audit log.

The client and domain charts come from the query log, so they appear only for those who may see it
(administrators and operators), and only as far as the privacy level keeps clients and domains.

**Reading it.** A cache hit rate of 70–90% is normal for an ISP. A sudden rise in SERVFAIL often means an
upstream problem or a broken DNSSEC domain; a client far above the others in *Top clients* may be infected or
attacked (see [Protection](#10-protection-attacks-pro)).

## 5. Zones (authoritative DNS)

**Zones** lists every hosted zone with its state, record count, default TTL, serial and when it changed.
Search by domain or description; filter by **Publish state** (*Published*, *Publishing*, *Publish failed*) and
**Active** / **Disabled**; sort by name or *Recently changed*.

### Creating a zone

*Zones → New zone*:

| Field | Example | Notes |
| --- | --- | --- |
| Domain | `example.com`, or a reverse zone `2.0.192.in-addr.arpa` | The zone apex. |
| Description | `Customer: Shop Ltd` | Optional, for your team. |
| Zone contact (SOA email) | `hostmaster@example.com` | Written into the SOA. |
| Default TTL (seconds) | `3600` | Used by records without their own TTL. |
| Name server 1, 2… | `ns1.isp.example`, `ns2.isp.example` | The servers the domain is delegated to; the first becomes the SOA primary. |
| IP address (glue) | `192.0.2.53` | Only for a name server **inside** this zone (`ns1.example.com` in `example.com`). |
| Template | *Website and mail at the ISP* | Optional: start with a template's records (below). |

DNSOne writes the zone file, checks it with `named-checkzone` and loads it into BIND; you add records on the next
page.

**Then delegate it**: at the domain's registrar, set the name servers to the ones you entered (and the glue, if
they are inside the domain). DNSOne cannot do that for you. Check with:

```bash
dig +short NS example.com @a.gtld-servers.net   # what the parent says
dig +short SOA example.com @192.0.2.53          # what this server answers
```

### Importing a zone

*Zones → Import*: creates the zone with the SOA, name servers and records of:

- **A zone file (BIND format)**, uploaded or pasted, e.g. exported from BIND, cPanel or another panel. Without
  `$TTL`, records get the zone's default TTL.
- **A zone transfer (AXFR) from the current DNS server**: its **Server address** (e.g. `198.51.100.53`), **Port**
  (53) and, if it needs one, the **TSIG key name**, **algorithm** (hmac-sha256…) and **secret**. The old server
  must allow transfers to this server (`allow-transfer`).

Every record is checked as if typed in; what DNSOne does not manage is listed as skipped. **Preview** first:
nothing changes until you import. A zone created by a reseller or customer may need an administrator's
approval (below).

```
$ORIGIN example.com.
$TTL 3600
@    IN SOA ns1 hostmaster ( 1 7200 1800 1209600 300 )
@    NS  ns1
ns1  A   192.0.2.53
www  A   192.0.2.10
```

To add records to an **existing** zone from a file or transfer, use *Zone → Import* and choose **Merge** (add
what the zone does not have yet) or **Replace** (the zone ends up with exactly the imported records). The zone's
SOA settings are kept.

### Records

*Zone → Records*: add, edit, disable (kept but not published) or delete records. Search by name, value or
comment, and filter by type.

| Field | Example |
| --- | --- |
| Name | `www`, `mail`, `@` (the zone itself), `*.dev` (wildcard) |
| Type | `A` |
| Value | `192.0.2.10` |
| TTL | empty = the zone's default |
| Priority | MX and SRV only, e.g. `10` |
| Comment | `Web server, rack 4` |

Supported types: **A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, PTR, DS, TLSA, SSHFP, NAPTR, HTTPS, SVCB** and
**ALIAS**. Examples:

| Name | Type | Value |
| --- | --- | --- |
| `@` | A | `192.0.2.10` |
| `@` | AAAA | `2001:db8::10` |
| `www` | CNAME | `example.com.` |
| `@` | MX | priority `10`, `mail.example.com.` |
| `@` | TXT | `v=spf1 mx include:_spf.isp.example -all` |
| `_dmarc` | TXT | `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com` |
| `sel1._domainkey` | TXT | `v=DKIM1; k=rsa; p=MIIBIjANBgkq…` (long values are split for you) |
| `@` | CAA | `0 issue "letsencrypt.org"` |
| `_sip._tcp` | SRV | priority `10`, `5 5060 sip.example.com.` (weight, port, target) |
| `@` | ALIAS | `myapp.cdn.example.` |
| `10` (in a reverse zone) | PTR | `host10.example.com.` |

- A value ending in a dot is a full name; without it, the zone is appended (`mail` → `mail.example.com.`).
- **ALIAS** is a CNAME that is allowed at the zone apex. DNSOne publishes the target's A/AAAA addresses and
  republishes within 5 minutes when they change.
- A CNAME must be alone at its name; DNSOne refuses combinations BIND would reject, and says why.
- TXT values can be long (SPF, DKIM): DNSOne splits them correctly.
- In a DNSSEC-signed zone, TTLs above the server's limit (a week by default) are refused.

### Publishing

Every change is published within seconds. The zone's badge shows:

| State | Meaning |
|---|---|
| published | BIND serves exactly what you see |
| publishing / pending | a change is on its way (a few seconds) |
| publish failed | BIND refused the change; **the previous version is still served**. The red box says why. Fix it and the next change publishes, or use *Publish now* |

Each publish raises the SOA serial (`YYYYMMDDnn`, e.g. `2026110603`). The zone page shows the **Serving serial**,
so you can compare it with `dig +short SOA example.com @<server>`.

### Approving zones made by resellers and customers

A zone a reseller or customer creates is served to the internet at once, but **this server's resolver keeps
answering it from the public DNS** until an administrator approves it, so nobody can take over a domain they do
not hold for your subscribers. Administrators see **Approve zone** on such a zone: approve only a domain that
account really holds.

### SOA and settings, zone file

- *SOA and settings*: default TTL, primary name server, contact, refresh / retry / expire, negative cache TTL,
  and the description. Typical: refresh `7200`, retry `1800`, expire `1209600`, negative TTL `300`.
- *Zone file*: the exact file BIND loads, as a read-only preview, and *Download*.
- *Disable zone*: BIND stops answering for it; records are kept. *Delete zone* removes it for good (you type the
  name to confirm).

### History and rollback

*Zone → History*: every publish that changed the zone (the last 100), with its serial, when, the number of
records, what changed and who changed it. *Show* any version, then **Roll back to this version**: the zone's
records and SOA settings become that version's again, as a new change (which is itself in the history, so it can
be undone). Status, DNSSEC and transfers are not part of a version.

**Example.** Someone deleted the MX record at 14:02. Open History, show the version published at 13:40, and roll
back: mail flows again within seconds.

### Templates

*Zone templates*: a set of records (and optionally name servers, contact and default TTL) with variables, for
zones that all look alike.

| Template field | Example |
| --- | --- |
| Name, Description | `Website and mail at the ISP` |
| Variables | `ip` asked as *Web server address*, default empty; `mx` asked as *Mail server*, default `mail.isp.example.` |
| Records | `@ A {ip}`, `www CNAME @`, `@ MX 10 {mx}`, `@ TXT "v=spf1 mx -all"` |
| Zone contact | `hostmaster@{zone}` |

`{zone}` is always available. Use a template under **New zone**, or *Zone → Template* to add its records to an
existing zone. Records that already exist or conflict are skipped and listed.

### Reverse DNS for a whole subnet

In a reverse zone, *Zone → Reverse DNS*:

| Field | Example |
| --- | --- |
| Subnet | `198.51.100.0/24` (inside the zone; at most 65,536 addresses at a time) |
| Name pattern | `host-{a}-{b}-{c}-{d}.dyn.isp.example.` |
| TTL | empty for the default |
| Replace records already there | off keeps existing PTRs |
| Also add the matching A/AAAA records | on: forward-confirmed reverse DNS, which mail servers check |

`{a}`…`{d}` are the address's four numbers, so `198.51.100.7` gets
`7.100.51.198.in-addr.arpa. PTR host-198-51-100-7.dyn.isp.example.`. **Preview** first.

### Dynamic DNS

For routers, home servers and certbot. An administrator turns it on in *Settings → DNS server* (**Dynamic DNS
updates**: from customer networks, or from anywhere where the key decides). Then *Zone → Dynamic DNS → New key*:

| Field | Example | Notes |
| --- | --- | --- |
| Key name | `router` | A single word becomes `router.example.com.` |
| Names it may change | `home`, `_acme-challenge`, `*.dyn` | Relative to the zone; `@` is the apex; `*.dyn` is every name below `dyn`. |
| Record types | A and AAAA by default; add TXT for certbot | |
| Algorithm | hmac-sha256 | |
| Secret | empty | Empty makes a new random 256-bit secret. |
| Comment | `Office MikroTik` | |

The secret is shown once, with ready-made settings for nsupdate, routers (dyndns2) and certbot (see
[Automation](#14-automation-api-dynamic-dns-certbot)). Every update is checked, audited and kept in the zone's
history. **Make a new secret** replaces it; **Last used** shows when it was used.

### Zone transfers to secondaries (Pro)

*Zone → Transfers*: let other name servers (for example a customer's own) keep a copy of the zone.

- **Allow a secondary**: its **address** (e.g. `198.51.100.53`; with **Notify it when the zone changes** and the
  notify port) or a **network** (e.g. `2001:db8::/64`: allowed to transfer, not notified; the secondary checks the
  serial every SOA refresh). A comment such as `ns2 at the customer`. Up to 20 entries.
- **Require a key**: transfers must also be signed with a TSIG key. The secret is shown once, with the
  configuration for a BIND secondary. Make a new key at any time; secondaries using the old one stop receiving
  updates until they get it. **Stop requiring** turns it off.
- The secondary transfers from this server's DNS address, port 53.
- **Every other transfer is refused.**

On the customer's BIND secondary:

```
key "example.com-xfr" { algorithm hmac-sha256; secret "base64secret=="; };
server 192.0.2.53 { keys { "example.com-xfr"; }; };
zone "example.com" { type secondary; primaries { 192.0.2.53; }; file "example.com.db"; };
```

### DNSSEC

*Zone → DNSSEC → Sign this zone*: BIND creates a key and signs the zone. Then:

1. Give the **DS record** shown to your registrar (some ask for the DNSKEY instead, also shown), e.g.
   `example.com. 3600 IN DS 12345 13 2 9F86D081…`. Registries that read **CDS** records take it from the zone by
   themselves (the tab shows the CDS once BIND publishes it; with the default timings that is about a week after
   signing).
2. DNSOne checks the parent every 5 minutes (or *Check the parent now*). When the DS is there, the tab says
   **"signed and secure"**.

If the **parent zone is hosted here too** (e.g. `customer.isp.example` under `isp.example`, with NS records for it
in the parent), you do nothing: DNSOne puts the DS records in the parent by itself.

- **Roll the key**: replaces the signing key safely. The new key's DS must reach the parent (by itself with a
  hosted parent or a CDS-reading registry, otherwise give the new DS to the registrar when the tab shows it). The
  old key goes after BIND has re-signed the zone (days). You can't start a second rollover before the first has
  finished.
- **Stop signing**: remove the DS at the registrar first and wait a day (DNSOne refuses otherwise, because
  validating resolvers would fail the zone). With a hosted parent DNSOne removes it for you.

Check from anywhere:

```bash
dig +dnssec +short DS example.com          # the parent's DS
dig +dnssec SOA example.com @192.0.2.53    # RRSIG records in the answer
delv example.com SOA                       # "fully validated" when the chain is complete
```

## 6. The resolver for your customers

Customers whose addresses are in *Settings → DNS server → Customer networks* may use this server as their
resolver; everyone else only gets answers for the zones hosted here.

- **DNSSEC validation** is always on: forged or broken answers become SERVFAIL. Your own hosted zones are exempt
  (they resolve for customers even before they are delegated).
- **Rate limits**: per customer address (or IPv6 /64), with a higher limit for **NAT addresses** (CGNAT gateways
  that carry many homes). Queries above the limit are dropped.
- **Encrypted DNS** (if your server has a certificate): DNS over TLS on port 853 (Android "Private DNS": enter the
  server's name) and DNS over HTTPS at `https://<name>/dns-query`.
- **Serve-stale**: when a site's name servers are down, customers keep getting its last answer for up to the set
  number of hours (*Settings → DNS server → Resolver*).
- **EDNS Client Subnet** (off by default): for the CDN domains you list, the customer's /24 (IPv6 /56) is passed
  on so the CDN answers with a nearby server. Never sent for private or CGNAT addresses, and never to domains you
  did not list.

### Giving it to customers

| Where | Setting |
| --- | --- |
| PPPoE (RadiusOne or your BRAS) | Primary DNS `192.0.2.53`, secondary the second node of a cluster |
| DHCP | option 6 (domain-name-servers) `192.0.2.53` |
| IPv6 | RDNSS / DHCPv6 `2001:db8::53` |
| Android | Settings → Private DNS → `dns.isp.example` (DoT) |
| Browsers | Secure DNS → custom `https://dns.isp.example/dns-query` (DoH) |

Test from a customer address:

```bash
dig example.org @192.0.2.53                      # recursion: answers
dig +short doubleclick.net @192.0.2.53           # blocked: NXDOMAIN (or your block page address)
kdig -d @dns.isp.example +tls example.org        # DNS over TLS
curl -sH 'accept: application/dns-json' 'https://dns.isp.example/dns-query?name=example.org&type=A'
```

From an address outside Customer networks, only hosted zones answer; other names are REFUSED.

## 7. Ad-blocking and client groups

### Ad-blocking

*Ad-blocking* has four tabs: **Lists**, **Rules**, **Block policy** and **Check a domain**.

**Lists: blocklists and allowlists.** Subscribe to lists by URL:

| Field | Example |
| --- | --- |
| Name | `StevenBlack unified` |
| URL | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` |
| Kind | blocklist or allowlist |
| Format | *Detect automatically*, *Hosts file (0.0.0.0 domain)*, *One domain per line* or *Adblock (`\|\|domain^`)* |
| Use this list | which client groups use it (every group, or chosen ones) |

Lists are downloaded every 6 hours. Allowlists win over blocklists and block rules. The list shows each list's
status, domain count, when it was updated and checked, and which groups use it. **See list** shows the domains of
the last download, with a search, and **Download .txt** saves them all. Use the raw file's address
(`raw.githubusercontent.com/…`), not GitHub's page (`github.com/…/blob/…`), and a list of domains, not a list of
other lists' addresses (add each of those lists instead).

**Rules: block or allow one domain.**

| Field | Example | Notes |
| --- | --- | --- |
| Action | *Block (default policy)*, *Allow (whitelist)*, *Block with NXDOMAIN*, *Block with empty answer* or *Redirect to…* | Allow always wins. A rule with its own action keeps it whatever the block policy says. |
| Domain | `ads.example.com` | Blocks it and, by default, everything below it. |
| Match | domain or regular expression | Regex example: `^ad[s0-9]*\.` |
| Applies to | everyone, or one client group | |
| Comment | `Ticket 4512` | |

**Import** adds up to 50,000 domains at once, one per line (`#` lines ignored), as block or allow rules.

**Block policy**: what a blocked name answers:

| Answer | What the customer sees |
| --- | --- |
| Does not exist (NXDOMAIN) | The default: the browser says the site cannot be found. |
| No data | An empty answer. |
| Null IP | `0.0.0.0` / `::`. |
| Redirect to | Your own page, by IP (`192.0.2.80`, returned as A/AAAA) or host name (`block.isp.example`, returned as CNAME): a walled garden. |

**Subdomains of blocked names**: also block every subdomain of a blocked name from lists and rules
(`ads.example.com` blocks `x.ads.example.com`). The tab also shows the **Response policy zone** the Recursor
loaded (last build and serial).

**Check a domain**: is it blocked, for which group, and by which list or rule? For example `doubleclick.net` →
*Blocked for Default: listed in StevenBlack unified*.

**Pause blocking** for everyone or for one group, for N minutes or until resumed. Court orders and Safe Search
stay on while paused.

Changes reach customers within about a minute (blocked answers are cached for at most 60 seconds).

### Client groups

*Client groups*: different rules for different customers, e.g. *Family filter*, *Business (no blocking)*.

1. **New client group**: a name and description.
2. **Clients**: add networks or single addresses (`192.0.2.0/24`, `203.0.113.7`, `2001:db8::/48`) with a comment,
   or **Import** many at once, one per line (text after `#` becomes the comment; networks already in a group are
   skipped, not moved).
3. **Settings** of the group:
   - **Ad-blocking on for these clients** (off: no list, rule or regex applies to them);
   - its own lists and rules;
   - **Safe Search**: Google, Bing and DuckDuckGo always filter explicit results (kept while blocking is paused);
   - **YouTube**: no restriction, restricted mode moderate, or strict;
   - **DNS64**: IPv6-only clients reach IPv4-only sites (needs a NAT64 gateway; the prefix is in Settings → DNS
     server).

A customer belongs to the group of its **most specific** network; everyone else is in *Default*. **Which group
is a client in?** answers for any address, e.g. `192.0.2.15` → *Family filter (192.0.2.0/24)*.

**Example: a family package.** Group *Family filter* with the subscriber pool `100.64.20.0/22`, ad-blocking on,
an adult-content blocklist, Safe Search on and YouTube *strict*. Customers on that package get it as soon as
RadiusOne gives them an address from that pool.

## 8. Court-ordered blocking (Pro)

*Court orders*: names a court or regulator ordered blocked. Separate from ad-blocking on purpose:

- They apply to **every customer and every group**, ahead of allow rules, allowlists and pauses.
- `example.com` blocks the name and everything below it; `*.example.com` only what is below it.
- Each entry records the authority, the order's reference and date, and who added it.
- Entries are never deleted: *Lift* (one name, or a whole order) with a reason; the list keeps the history.
  *Export CSV* is the record for the regulator.
- Blocked names answer with the **legal notice page** if one is set up, otherwise "does not exist", with the DNS
  extended error "Censored".

### Add an order

| Field | Example |
| --- | --- |
| Ordered by | `Court of First Instance, Tirana` |
| Reference | `Decision no. 1234/2026` |
| Date of the order | `2026-10-30` |
| Domains, one per line | `blocked-site.example`, `*.mirror.example` |
| Notes | anything for the record |

Every name of the order is blocked for every customer within a minute. The **Orders** and **Names blocked** tabs
list them; filter by *Blocked now*, *Lifted* or *All*, and search by domain, reference or authority. To lift:
**Lift**, with a reason such as `Order revoked on appeal, decision no. 5678/2026`; the entry stays, marked lifted.

### Legal notice page

*Court orders → Notice page*: a page customers see instead of the blocked site (HTTP 451). Set a **Title**, a
**Message**, whether to **show the authority and the reference** of the order, and the **Page address** (IPv4,
e.g. `203.0.113.80`, and optionally IPv6) that reaches this server's nginx. Blocked names then answer with that
address, so browsers show the notice; HTTPS links show a connection error instead, because no certificate can
match a blocked name.

Check: `dig +short blocked-site.example @192.0.2.53` returns the page address (or NXDOMAIN without one).

## 9. Query log

*Query log* (if your server keeps one): who asked for what, and what they got.

- **Search and filter** by client (IP address), domain, type (A, AAAA…), reply (NOERROR, NXDOMAIN…) and status
  (ok, blocked, allowed by a rule, court order); click a client or name to see only that. Each row shows the time,
  client, domain, type, reply, status and time taken.
- **Live** shows queries as they arrive.
- **Allow / block this domain** directly from a row (adds a rule).
- **Top lists**: top permitted and blocked domains, top clients, clients with the most blocked queries, query
  types and reply codes, for a chosen period; **History**: queries and blocked queries per day, 30 days.
- **Privacy** (*Settings → Privacy*): see [Settings](#12-settings).
- **Export** (Pro) (*Settings → Query log export*): send every answer (or only blocked ones) to your SIEM by
  syslog, or the raw DNS messages by dnstap.

**Example: "my bank's site does not open".** Filter client `100.64.20.15`, domain `bank.example`: the row shows
*blocked · listed in …*. Use **Allow this domain**, and the customer's next try works within a minute.

## 10. Protection (attacks) (Pro)

*Protection* shows what dnsdist is blocking by itself and why:

| Kind | What it is | What happens |
|---|---|---|
| Random-subdomain attack | a domain asked for with thousands of names that do not exist ("water torture"), to overload its name servers | refused for everyone for a few minutes; never your hosted zones |
| Infected client (off by default) | a customer whose answers are mostly "does not exist" | its queries are dropped for a while |
| Amplification | a customer receiving far more data than a real user (its address is being spoofed) | answers are truncated, so real clients retry over TCP and spoofed ones get nothing |
| Query / SERVFAIL flood | a customer far above its query rate | refused for a minute |

- **Blocked now** on each node, the **Last 24 hours** by kind, the **Most blocked** targets, and a week of
  **History** (one row per target and episode).
- **Block** a client or domain yourself:

  | Field | Example |
  | --- | --- |
  | Block | *A client address or network* (`203.0.113.66`, `198.51.100.0/24`) or *A domain (and every name below it)* |
  | Where | *DNS queries (dnsdist)*, or *Everything (firewall)* for a client (administrators; all traffic, not only DNS) |
  | For | 1 hour, 1 day, 1 week or until removed |
  | Reason | `Reflection attack, ticket 9921` |

  A client's queries are dropped and a domain gets REFUSED, on every node. **Unblock** lifts it.
- **Thresholds** can be changed. dnsdist looks at the last 10 seconds of traffic; floods above twice a client's
  query rate (Settings → DNS server) are always refused. The "infected client" rule is off by default because
  ad-blocked names also answer "does not exist": turn it on with a threshold above what a busy household sends.
- NAT addresses and the server itself are never blocked automatically.

## 11. Customers, resellers and quotas (Pro)

- **Resellers** create zones (which become theirs) and **customer accounts** under *Customers*. They can give their
  customers only their own zones, and see only their own customers.
- **Customers** see only the zones given to them, and change their records, dynamic DNS keys and transfers. They
  can't create or delete zones unless their role allows it.
- Zones a reseller or customer creates need an administrator's **approval** before this server's resolver uses
  them ([Approving zones](#approving-zones-made-by-resellers-and-customers)).
- **Quotas**, in the user dialog, for accounts limited to their own zones:
  - **Zones it may hold**;
  - **Records per zone**, checked when the account adds records (an administrator adding records to the
    customer's zone is not limited);
  - **API requests per minute**, console and app passwords together. Above it the API answers
    "429 Too many requests" with a `Retry-After`.

  Empty means no limit. A reseller's customers can't get more than the reseller has, and inherit the reseller's
  limits when left empty.

**Example: a hosting reseller.** Create user `webhost-ltd` with role *reseller*, zones it may hold `200`, records
per zone `500`. They sign in, create `shop.example`, and add customer `shop-owner` with only that zone. The
shop owner can change their records and nothing else; you approve `shop.example` once.

## 12. Settings

Administrators only, except where noted.

### Overview and software update

**System information** about this server, shortcuts to Users & access, Zones and Ad-blocking, and
**Software update**: see if a new DNSOne release exists, read **What is new**, and **Install update**. DNS keeps
answering; the console restarts by itself and reloads. **Update log** shows each step. If a step fails, the update
rolls back by itself. On a cluster, update every node, the primary first.

### Users

The account list shows username, name, role, sign-in (password or single sign-on), status, last login and zones.

| Field | Example | Notes |
| --- | --- | --- |
| Username, Full name, Email | `jane`, `Jane Doe` | |
| Role | operator | Built-in or custom. |
| Signs in with | A DNSOne password / Single sign-on | |
| Can sign in | on | Off blocks the account; its history stays. |
| Zones | `example.com`, `shop.example` | For roles limited to their own zones. |
| Reseller | `webhost-ltd` | The reseller who manages this customer. |
| Zones it may hold, Records per zone, API requests per minute | `10`, `200`, `60` | Quotas (Pro). |
| Turn off two-factor sign-in (lost phone) | | They set it up again at their next sign-in. |

**Roles** tab: custom roles (see [Who can do what](#3-who-can-do-what)).

From the server: `sudo dnsone-ctl create-admin jane --role admin` creates an operator or resets its password;
`--reset-two-factor` turns off two-factor.

### DNS server

| Setting | Example | What it does |
| --- | --- | --- |
| Customer networks | `100.64.0.0/10`, `198.51.100.0/22`, `2001:db8:1000::/36` | Only these may use the resolver (recursion and ad-blocking). The private ranges and loopback are always included. |
| NAT addresses | `203.0.113.1`, `203.0.113.2` | CGNAT or NAT gateways that carry many homes: they get the NAT rate limit and are never blocked automatically. |
| Rate limits | 200 queries/s with bursts to 400 per customer address; 5,000 / 10,000 per NAT address (the defaults) | Per IPv4 address or IPv6 /64; queries above them are dropped. |
| Public authoritative DNS | on | Anyone on the internet may ask for the zones hosted here (nothing else). Off: only customers. |
| DNS64 prefix | `64:ff9b::/96` | The /96 your NAT64 gateway translates; for groups with DNS64 on. |
| Dynamic DNS updates (RFC 2136) | Off / From customer networks / From anywhere (the key decides) | |

**Resolver**: **Serve stale answers for (hours)**, e.g. `12`; **EDNS Client Subnet** with its **Domains**
(`akamaiedge.net`, `cloudfront.net`), **IPv4 prefix sent** (`24`) and **IPv6 prefix sent** (`56`). Saving restarts
the Recursor (**Save and restart**): its cache starts empty, so resolution is slower for a few minutes.

Listen addresses stay in `/etc/dnsdist/dnsdist.conf` (they need a restart).

### Privacy

**What is kept** in the query log: *Show everything*, *Hide domains*, *Hide domains and clients*, or *Anonymous:
totals only*. Hidden
values are stored as "hidden"; queries already stored keep their detail until they expire or are erased. **Keep
queries for (hours)**, up to the server's limit (`DNSONE_QUERYLOG_RETENTION_HOURS`). **Erase now** deletes the log,
and optionally the statistics.

### Alerts

Send alerts when a service fails, a zone does not publish, a blocklist download fails, the DoT/DoH certificate is
about to expire, a node stops syncing or a query flood is blocked.

| Channel | Fields |
| --- | --- |
| Email | SMTP server (`smtp.isp.example`), port, encryption (STARTTLS 587, TLS 465, or none on 25 for a trusted relay), user and password, From (`dnsone@isp.example`), recipients (`noc@isp.example, oncall@isp.example`) |
| Webhook | URL (Slack, Mattermost, Rocket.Chat, Teams, or your own: JSON with a `text` field and the alerts), e.g. `https://hooks.slack.com/services/…` |
| Telegram | Bot token and chat id (e.g. `-1001234567890`) |

Plus: **Also warnings** (not only errors), **Send after (minutes)** (a problem must last this long, so reloads and one
slow probe stay quiet), **Remind every (hours)** (0 sends it once; a message follows when it is resolved).
**Open problems** lists what is wrong now on each node, since when and whether it was notified. Test from the
server with `sudo dnsone-ctl alerts test`.

**Prometheus**: every node serves its metrics at `https://<console>/api/metrics` for your Prometheus.

### Query log export (Pro)

- **Syslog**: send every answer (or *Blocked and court orders only*) as a syslog message: client, name, type,
  reply, verdict and client group. **Collector** (`siem.isp.example` or `192.0.2.50`), **Port**, **Protocol** (UDP,
  or TCP queued with reconnects), **Format** (RFC 5424 with key=value or JSON) and **Facility** (`local0`…). Privacy
  levels apply; messages are dropped, never DNS, if the collector is slow.
- **dnstap**: stream the raw DNS messages (queries and/or responses) from dnsdist in Frame Streams to a collector
  (`192.0.2.50:6000` or `/run/dnstap.sock`). Each node streams its own; no verdict and no privacy filtering.

### Single sign-on (Pro)

Operators sign in with your identity provider: Google Workspace, Microsoft Entra ID, Okta, Authentik, Keycloak or
any OpenID Connect provider. Register DNSOne there as a confidential client, with the redirect URI the page shows.

| Field | Example |
| --- | --- |
| Issuer | `https://login.microsoftonline.com/TENANT/v2.0` (DNSOne reads `<issuer>/.well-known/openid-configuration`) |
| Client id / Client secret | from the provider |
| Scopes | `openid email profile groups` |
| Console address | `https://dns.isp.example` |
| Button label | `Sign in with Microsoft` |
| Username from claim | `preferred_username` |
| Claim with the user's groups | `groups` (a dotted path such as `realm_access.roles` works) |
| Role mapping | *When the claim contains* `dns-admins` → *admin*; first match wins |
| Role when no mapping matches | *None: refuse the sign-in*, or a role for new accounts |
| Create a DNSOne account at a user's first sign-in | on |
| Only these email domains | `isp.example, noc.isp.example` |
| Signing out of DNSOne also signs out of the provider | optional |

### Backup

**Download a backup**: a JSON file with the sections you choose: *Zones and records*, *Ad-blocking: lists, groups,
rules, block policy*, *Settings: DNS server, privacy*, and court orders (Pro). Operators, passwords, app passwords, the
audit log and the query log are never included. **Restore** reads such a file and replaces the chosen sections,
for moving settings between servers. The nightly `dnsone-backup` timer keeps full database backups on the server
([Command reference](#16-command-reference)).

### Cluster (Pro)

Two or more DNSOne servers can serve the same customers: one **primary** and **replicas**. They share the
primary's database, so a change made on any server's console reaches every server within 30 seconds; the
replicas get the hosted zones from the primary's BIND. Give customers every server as a resolver (DNS 1, DNS 2 in
PPPoE or DHCP). Setting it up needs no terminal:

1. Install DNSOne on each server, at the **same version**. Only the primary needs a licence: one that covers every
   server of the cluster. The others may run DNSOne Community: they join with the cluster's licence.
2. On the **primary**, Settings → Cluster → *Servers in this cluster*: enter the **New server's address**
   (`192.0.2.54`), a **Name** (`dns2`) and **This server's address** (the one the new server reaches it on,
   `192.0.2.53`), and click **Add server**. In a few seconds the server is **ready to join**: click **Join key** and
   copy the key.
3. On the **new server**, Settings → Cluster → *Join a cluster*: paste the key and click **Join cluster**. BIND and
   DNSOne restart there (DNS keeps answering); after a minute sign in again **with the primary's accounts**. Both
   servers are listed under *Nodes*, and the primary shows the new one as **joined**.

What it sets up: on the primary, a MySQL account only the new server's address may use, and only over TLS; MySQL
and BIND listening on the primary's address; with ufw or the DNSOne firewall on, ports 3306 and 5301 open to that
server alone. On the new server: DNSOne pointed at the primary's database (checked against the primary's own
certificate) and BIND following the primary's catalog of zones. If a step fails, the new server keeps its own
configuration and the page shows what happened.

Without a firewall, the primary's MySQL listens on its address for everyone; only the cluster's accounts can sign
in, but turning the firewall on (Settings → Firewall, or ufw) is better.

**Leave the cluster** (on a replica) gives the server back its own database, users and zones as they were when it
joined. **Remove** (on the primary) deletes the server's database account, so a server removed without leaving
first stops working: leave first, then remove. While a server is a replica, its own backups (Settings → Backup)
still cover its standalone database, not the shared one: back up on the primary.

**Secondaries**: plain BIND servers that should also serve your hosted zones. **Configuration for a secondary**
gives a ready BIND configuration for this primary's address; or `sudo dnsone-ctl cluster secondary-config
--primary 192.0.2.53`.

### Firewall (Pro)

DNSOne can manage the server's firewall (nftables). Off until you turn on **DNSOne manages this server's
firewall**.

1. **Management networks**: where you administer from, e.g. `198.51.100.0/28`. SSH and the console (ports 22, 80,
   443) are always open to them, **whatever the rules say**, so you cannot lock yourself out with a rule. The page
   shows your current address; it must be inside.
2. **Open to everyone**: DNS (53, UDP and TCP), DNS over TLS (853), DNS over HTTPS (443), each switchable.
3. **Rules**, checked in order (**Move up / Move down**):

   | Field | Example |
   | --- | --- |
   | Action | Accept, Drop (silently) or Reject (tell the sender) |
   | Source | `192.0.2.54` or `192.0.2.0/24` |
   | Protocol | TCP, UDP, TCP and UDP, ICMP (not the essential types) or Everything |
   | Ports | `3306`, `80,443` or `1000-2000` |
   | For | Permanently, 1 hour, 1 day or 1 week |
   | Comment | `MySQL from the replica` |

4. Everything else is dropped. The server's own connections, loopback and essential ICMP always work.

Edits are a **draft** until you click **Apply**. Then:

- the server applies the rules, and **this page confirms it can still reach the server**. Keep the page open for
  those seconds;
- if it can't confirm within a minute (you locked yourself out), **the previous rules come back by themselves**;
- the other nodes of a cluster pick up the rules within a minute.

The preview shows the exact nftables rules. If the server also uses ufw, turn ufw off once DNSOne's firewall works
(with both, traffic must pass both). The firewall is not in backups: its rules belong to one server.

### License

DNSOne Community or Pro: this server's **ID** (a licence is issued for it), and **Licence key** to paste a key
(`DNSONE1.…`) from your PingOmni account. It shows who it is for, until when, and how many servers it covers. A
cluster needs one licence for all its servers, issued for any one of them (the primary's) and pasted on any of
them. With a key, the server registers with your PingOmni account and checks in twice a day (report only: Pro never
depends on it). An expired licence keeps the Pro features running as they were, but they cannot be changed until it
is renewed. **Remove** returns the server to Community.

## 13. Audit log

*Audit log*: every change anyone made (zones, records, rules, users, settings, sign-ins), with the time, the
operator, the action, the item and the details of what exactly changed, and from which address. Filter by person
(*Everyone* or one operator), by item type, and search by zone, domain, user or ID.

**Example**: search `example.com` to see who changed which record of that zone and when; combine with *Zone →
History* to roll back.

## 14. Automation: API, dynamic DNS, certbot

### The API

Everything the console does is in the API, documented at `https://<console>/api/docs` (interactive, with every
endpoint and field). Use an **app password** (*My profile → App passwords*): `Authorization: Bearer dno_…`.
Read-only app passwords can only read. App passwords have the same reach as their account (a customer's only its
zones), and quotas apply.

```bash
TOKEN=dno_xxxxxxxxxxxxxxxx
API=https://dns.isp.example/api

# List zones
curl -s -H "Authorization: Bearer $TOKEN" $API/zones

# Create a zone
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"example.com","soa_rname":"hostmaster@example.com","default_ttl":3600,
       "nameservers":[{"host":"ns1.isp.example"},{"host":"ns2.isp.example"}]}' \
  $API/zones

# Records of zone 42, then add one (the zone's id is in the list above)
curl -s -H "Authorization: Bearer $TOKEN" $API/zones/42/records
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"www","type":"A","value":"192.0.2.10","ttl":300,"comment":"web server"}' \
  $API/zones/42/records

# Publish now, and download the zone file
curl -s -X POST -H "Authorization: Bearer $TOKEN" $API/zones/42/publish
curl -s -H "Authorization: Bearer $TOKEN" $API/zones/42/export

# Health, for monitoring (no token needed): {"status":"ok"}, HTTP 503 on errors
curl -s https://dns.isp.example/api/health
```

A record's fields are `name`, `type`, `value`, `ttl`, `priority`, `disabled` and `comment`; edit one with `PATCH
$API/zones/42/records/<id>` and delete it with `DELETE`. Every endpoint and field is in `/api/docs`.

### Dynamic DNS for routers (dyndns2)

The "custom" provider in most routers: server = the console's name, path `/nic/update`, username = the key's
first label, password = the key's secret. For example:

```bash
curl -u router:SECRET 'https://dns.isp.example/nic/update?hostname=home.example.com&myip=198.51.100.7'
# myipv6=2001:db8::7 for AAAA; several host names separated by commas (up to 10)
```

On MikroTik, a scheduler script can call the same URL with `/tool fetch`.

### nsupdate (RFC 2136)

```bash
nsupdate -y hmac-sha256:router.example.com.:SECRET <<'END'
server 203.0.113.53
zone example.com.
update delete home.example.com. A
update add home.example.com. 300 A 198.51.100.7
send
END
```

### certbot wildcard certificates

Make a dynamic DNS key that may change `_acme-challenge` (type TXT), then use the `dns-rfc2136` plugin:

```ini
# /etc/letsencrypt/rfc2136.ini (chmod 600)
dns_rfc2136_server = 203.0.113.53
dns_rfc2136_port = 53
dns_rfc2136_name = certbot.example.com.
dns_rfc2136_secret = SECRET
dns_rfc2136_algorithm = HMAC-SHA256
```

```bash
sudo apt install python3-certbot-dns-rfc2136
sudo certbot certonly --dns-rfc2136 --dns-rfc2136-credentials /etc/letsencrypt/rfc2136.ini \
  -d example.com -d '*.example.com'
```

### Prometheus

`/api/metrics` on every node (see *Settings → Alerts*).

## 15. Installing and updating

### Install

On a fresh **Ubuntu 24.04 LTS** server (2 GB RAM, 4 GB free disk), as root:

```bash
curl -fsSL https://raw.githubusercontent.com/Pingomni/dnsone/main/install.sh -o install.sh
sudo bash install.sh
```

It asks for the DNS address, the console address and host name, and the management network (each with a
suggestion), installs the latest release with BIND, the Recursor, dnsdist, MySQL and nginx, and prints the console
URL with the first administrator's password. Without questions:

```bash
sudo bash install.sh --yes --server-ip 192.0.2.53 --mgmt-ip 192.0.2.53 --mgmt-net 198.51.100.0/28 \
  --fqdn dns.isp.example --client-networks 198.51.100.0/22,2001:db8:1000::/36 \
  --admin jane --admin-email jane@isp.example --timezone Europe/Tirane --ufw
```

| Option | What it does |
| --- | --- |
| `--server-ip IP` | The DNS address customers use. |
| `--mgmt-ip IP` | The address the console listens on (nginx, 443); default: the server IP. |
| `--mgmt-net CIDR` | Who may reach SSH and the console (for `--ufw` and the summary). |
| `--fqdn NAME` | The console's host name (for the TLS certificate). |
| `--client-networks LIST` | Customer networks allowed to use the resolver, comma-separated (added to 10/8, 172.16/12, 192.168/16 and 100.64/10). |
| `--admin NAME`, `--admin-email EMAIL` | The first administrator (default `admin`). |
| `--timezone ZONE` | The time zone the console shows times in. |
| `--version vX.Y.Z` | A given release instead of the latest. |
| `--source DIR` | Install from a built source tree. |
| `--ufw` | Also turn on ufw: DNS open, SSH and the console from `--mgmt-net` only. Without it, use DNSOne's firewall (Pro). |
| `--yes` | No questions. |

Running it again is safe: it keeps the secrets, the database and its files. On a server where DNSOne is installed
it stops: use `sudo dnsone-update`.

### Update

From the console (**Settings → Overview → Software update**), or:

```bash
dnsone-update --check      # is there a newer release?
sudo dnsone-update         # download, check, back up, install, verify; rolls back by itself on failure
sudo dnsone-update v1.5.16 # a given release
```

On a cluster: every node, the primary first. DNS keeps answering; a new minor version (1.4 → 1.5) restarts dnsdist
(a second or two) and may restart the Recursor (its cache starts empty).

## 16. Command reference

`dnsone-ctl` runs the DNSOne CLI as the `dnsone` user with the settings in `/etc/dnsone/dnsone.env`.

| Command | What it does |
| --- | --- |
| `sudo dnsone-status` | systemd state of every service and timer, then DNSOne's health probes. Exit 0 healthy, 1 error, 2 warning. |
| `sudo dnsone-ctl status` | The probes only: MySQL, rndc, BIND over DNS, Recursor and dnsdist APIs, publishing, RPZ, disk. |
| `sudo dnsone-ctl create-admin jane --name "Jane Doe" --email jane@isp.example --role admin` | Creates an operator, or resets its password (asked). `--reset-two-factor` for a lost phone. |
| `sudo dnsone-ctl zones list` | Every zone with its state and serial. |
| `sudo dnsone-ctl zones publish example.com` | Publishes one zone now. |
| `sudo dnsone-ctl zones reconcile [--force]` | Brings every zone file in line with MySQL; `--force` rewrites all, even up to date. |
| `sudo dnsone-ctl rpz refresh` | Downloads the blocklists now. |
| `sudo dnsone-ctl rpz build` | Rebuilds the response policy zone and loads it. |
| `sudo dnsone-ctl rpz pause --minutes 30 [--group Family]` | Pauses ad-blocking (0 minutes: until resumed). |
| `sudo dnsone-ctl rpz resume [--group Family]` | Resumes it. |
| `sudo dnsone-ctl sync` | Brings this node up to date with MySQL (settings, groups, firewall). |
| `sudo dnsone-ctl stats collect` | Collects statistics now. |
| `sudo dnsone-ctl alerts check` / `alerts test` | Runs the alert checks / sends a test to every channel. |
| `sudo dnsone-ctl license check-in` | Registers with the PingOmni account now. |
| `sudo dnsone-ctl cluster nodes` | The cluster's nodes and their sync state. |
| `sudo dnsone-ctl cluster secondary-config --primary 192.0.2.53 [--port 5301]` | BIND configuration for a secondary. |
| `sudo dnsone-ctl migrate [--status]` | Applies (or lists) database migrations. |
| `sudo dnsone-update [--check \| vX.Y.Z]` | Updates DNSOne. |
| `sudo bash /opt/dnsone/ops/dnsone-postinstall` | Brings the system configuration in line with the installed release (safe to run again). |

### Backups and restore

`dnsone-backup.timer` runs every night at 03:15 and keeps 14 days (the newest three always):
`/var/backups/dnsone/YYYYmmdd-HHMMSS/` with `dnsone.sql.gz`, `files.tar.gz` (zones, BIND, DNSOne, Recursor,
dnsdist and nginx configuration, DNSSEC keys, TLS files) and `SHA256SUMS`. Copy it off the server as well.

```bash
sudo systemctl start dnsone-backup.service      # a backup now
ls -l /var/backups/dnsone/

# Restore
R=/var/backups/dnsone/20261106-031500
(cd $R && sha256sum -c SHA256SUMS)
sudo systemctl stop dnsone-api dnsone-reconcile.timer dnsone-rpz.timer
zcat $R/dnsone.sql.gz | sudo mysql dnsone
sudo mkdir -p /root/restore && sudo tar -xzf $R/files.tar.gz -C /root/restore   # copy back what you need
sudo systemctl start dnsone-api dnsone-reconcile.timer dnsone-rpz.timer
sudo dnsone-ctl zones reconcile --force && sudo dnsone-ctl rpz build
```

### Logs and live views

```bash
journalctl -u dnsone-api -f                         # the API
journalctl -u 'dnsone-*' --since today              # API and timers
tail -f /var/log/dnsone/dnsone.log                  # the same, as a file
journalctl -u named -u pdns-recursor -u dnsdist --since -1h
sudo dnsdist -c -e 'showServers()'                  # dnsdist's back ends
sudo dnsdist -c -e 'topClients(10)'                 # busiest clients right now
sudo rec_control get-all | grep -E 'questions|cache-hits|policy-result'
sudo rec_control wipe-cache example.com$            # forget one name from the cache
```

If the firewall locked you out, from the console: `sudo nft delete table inet dnsone` removes DNSOne's rules
until the next Apply or reboot.

## 17. Good to know

- **Changes are live in seconds**: zones within a few seconds, ad-blocking within a minute, DNS server settings
  within 2 seconds. Resolvers elsewhere on the internet may still have the old answer cached until its TTL runs
  out: lower a record's TTL a day before a planned change.
- **A failed publish never breaks a zone**: the previous version keeps being served.
- **Customers see hosted zones immediately**, even before the domain is delegated at the registrar (zones made by
  resellers and customers once approved).
- **NXDOMAIN for blocked names**: if customers report a site "does not exist", check it in *Ad-blocking → Check a
  domain*, or look it up in the query log.
- **Pausing** ad-blocking does not pause court orders or Safe Search.
- **Two-factor**: keep your recovery codes; without them and your phone, an administrator must turn it off for you.
- **Software updates** keep DNS answering and roll back by themselves if they fail.
- **Backups**: the server backs itself up every night. *Settings → Backup* is for moving settings between servers
  or keeping your own copy.

### Troubleshooting

| Symptom | What to check |
| --- | --- |
| Customers get REFUSED for everything | Their addresses are not in *Customer networks*. |
| One site does not resolve | Query log for the name: blocked (allow it), SERVFAIL (often broken DNSSEC at that domain: `delv name`), or NXDOMAIN from upstream. |
| A zone shows *publish failed* | The red box says what BIND refused; fix the record, or roll back in History. |
| A new zone does not answer from the internet | Delegation at the registrar (`dig NS domain @a.gtld-servers.net`), and *Public authoritative DNS* on. |
| DNSSEC stays "waiting for the parent" | The DS at the registrar must match the one shown; registries can take hours. |
| A customer is slow or blocked | Protection: is its address blocked? Is it a NAT gateway missing from *NAT addresses*? |
| Blocklist shows an error | The URL must be the raw file; check it opens with `curl -I`. |
| Alerts do not arrive | `sudo dnsone-ctl alerts test`, then the SMTP/webhook/Telegram settings. |
| The console does not open | `sudo dnsone-status`; `journalctl -u dnsone-api -n 50`; nginx `sudo nginx -t`. |
| Where to get help | The red messages in the console say what to fix; the audit log says who changed what; administrators find everything else in [RUNBOOK.md](RUNBOOK.md). |
