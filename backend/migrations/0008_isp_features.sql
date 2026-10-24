-- DNSOne schema, version 0008 (1.4): customer and reseller self-service, zone templates and history,
-- court-ordered blocking, Safe Search and DNS64 per group, ALIAS records, dynamic DNS, single sign-on.
-- Every change is additive; 1.3 ignores the new tables and columns.

-- ---------------------------------------------------------------------------
-- Roles and per-zone permissions
-- ---------------------------------------------------------------------------

-- all: the role's zone permissions cover every zone. assigned: only the zones given to the user
-- (user_zones), and the zones the user creates. Customers and resellers are 'assigned'.
ALTER TABLE roles ADD COLUMN zone_scope ENUM('all','assigned') NOT NULL DEFAULT 'all' AFTER permissions;

-- The reseller who created a customer account; resellers manage only their own customers.
ALTER TABLE users
    ADD COLUMN parent_id INT UNSIGNED NULL AFTER role_id,
    ADD KEY idx_users_parent (parent_id),
    ADD CONSTRAINT fk_users_parent FOREIGN KEY (parent_id) REFERENCES users (id) ON DELETE SET NULL;

CREATE TABLE user_zones (
    user_id     INT UNSIGNED  NOT NULL,
    zone_id     INT UNSIGNED  NOT NULL,
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, zone_id),
    KEY idx_user_zones_zone (zone_id),
    CONSTRAINT fk_user_zones_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_zones_zone FOREIGN KEY (zone_id) REFERENCES zones (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- New permissions. Creating zones is now its own permission (it was part of zones.manage).
UPDATE roles SET permissions = JSON_ARRAY_APPEND(permissions, '$', 'zones.create')
 WHERE JSON_CONTAINS(permissions, '"zones.manage"') AND NOT JSON_CONTAINS(permissions, '"zones.create"');
UPDATE roles SET permissions = JSON_ARRAY_APPEND(permissions, '$', 'templates.manage')
 WHERE name IN ('admin', 'operator') AND NOT JSON_CONTAINS(permissions, '"templates.manage"');
UPDATE roles SET permissions = JSON_ARRAY_APPEND(permissions, '$', 'legal.view')
 WHERE name IN ('admin', 'operator') AND NOT JSON_CONTAINS(permissions, '"legal.view"');
UPDATE roles SET permissions = JSON_ARRAY_APPEND(permissions, '$', 'legal.manage')
 WHERE name = 'admin' AND NOT JSON_CONTAINS(permissions, '"legal.manage"');

INSERT INTO roles (name, description, permissions, zone_scope, built_in) VALUES
('reseller', 'Creates zones and customer accounts, and manages them; sees only its own zones and customers.',
 JSON_ARRAY('zones.view', 'zones.manage', 'zones.create', 'users.customers'), 'assigned', 1),
('customer', 'Manages the records of the zones given to it; nothing else.',
 JSON_ARRAY('zones.view', 'zones.manage'), 'assigned', 1);

-- ---------------------------------------------------------------------------
-- Zone templates and zone history
-- ---------------------------------------------------------------------------

-- Records a new zone starts with (or that are added to one), with {variables} filled in on use.
CREATE TABLE zone_templates (
    id           INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    name         VARCHAR(64)   NOT NULL,
    description  VARCHAR(255)  NOT NULL DEFAULT '',
    -- NULL: the zone keeps the form's value.
    default_ttl  INT UNSIGNED  NULL,
    -- Zone contact, may use {zone}; '' for the form's value.
    soa_rname    VARCHAR(253)  NOT NULL DEFAULT '',
    -- [{"host": "ns1.isp.example.", "address": null}]
    nameservers  JSON          NOT NULL,
    -- [{"name": "ip", "label": "Web server address", "default": ""}]
    variables    JSON          NOT NULL,
    -- [{"name": "www", "type": "A", "value": "{ip}", "ttl": null, "priority": null, "comment": ""}]
    records      JSON          NOT NULL,
    created_by   VARCHAR(64)   NOT NULL DEFAULT '',
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_zone_templates_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- What each publish put live: the zone's settings and every record, compressed. Rolling back
-- restores one of them as a new change. A publish that changed nothing adds no version.
CREATE TABLE zone_versions (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    zone_id       INT UNSIGNED    NOT NULL,
    serial        INT UNSIGNED    NOT NULL,
    revision      INT UNSIGNED    NOT NULL,
    record_count  INT UNSIGNED    NOT NULL,
    -- SHA-1 of the uncompressed snapshot: an unchanged zone is not stored twice.
    digest        CHAR(40)        CHARACTER SET ascii NOT NULL,
    -- zlib-compressed JSON {"zone": {...settings}, "records": [...]}.
    snapshot      LONGBLOB        NOT NULL,
    -- Differences from the previous version: {"added": n, "removed": n, "settings": [...]}.
    changes       JSON            NULL,
    -- Operators whose changes this version contains (from the audit log).
    actors        JSON            NULL,
    created_at    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    KEY idx_zone_versions_zone (zone_id, id),
    CONSTRAINT fk_zone_versions_zone FOREIGN KEY (zone_id) REFERENCES zones (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ALIAS: a CNAME-like record allowed at the apex. The zone generator resolves its target and publishes
-- the addresses as A/AAAA records; the reconcile timer re-resolves and republishes when they change.
ALTER TABLE records
    MODIFY COLUMN type ENUM('A','AAAA','CNAME','MX','TXT','NS','SRV','CAA','PTR','DS','TLSA','SSHFP','NAPTR','HTTPS','SVCB','ALIAS') NOT NULL;

-- Last addresses each ALIAS target resolved to: {"target.": {"A": [...], "AAAA": [...], "ttl": n, "at": "..."}}.
-- Kept so a target that cannot be resolved for a while keeps its last answer instead of disappearing.
ALTER TABLE zones ADD COLUMN alias_cache JSON NULL AFTER last_error;

-- ---------------------------------------------------------------------------
-- Court-ordered blocking
-- ---------------------------------------------------------------------------

-- Names a court or regulator ordered blocked. Separate from ad-blocking: applies to every client and
-- every group, cannot be paused or allowlisted, and answers with the legal notice page. Entries are
-- never deleted, only lifted, so the list keeps who ordered, added and lifted every block.
CREATE TABLE legal_blocks (
    id           INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    -- 'example.com' (that name and, like ad-blocking, every name below it) or '*.example.com' (only below).
    pattern      VARCHAR(253)  NOT NULL,
    authority    VARCHAR(128)  NOT NULL,
    reference    VARCHAR(128)  NOT NULL,
    ordered_on   DATE          NULL,
    notes        VARCHAR(1000) NOT NULL DEFAULT '',
    active       TINYINT(1)    NOT NULL DEFAULT 1,
    created_by   VARCHAR(64)   NOT NULL DEFAULT '',
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lifted_at    DATETIME      NULL,
    lifted_by    VARCHAR(64)   NULL,
    lift_reason  VARCHAR(255)  NULL,
    updated_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    -- One active entry per name; lifted ones can repeat.
    active_pattern VARCHAR(253) AS (IF(active = 1, pattern, NULL)) STORED,
    PRIMARY KEY (id),
    UNIQUE KEY uq_legal_blocks_active (active_pattern),
    KEY idx_legal_blocks_pattern (pattern),
    KEY idx_legal_blocks_reference (reference)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Appending to an ENUM is an instant change in MySQL 8, even on a large query log.
ALTER TABLE query_log MODIFY COLUMN status ENUM('ok','blocked','allowed','legal') NOT NULL;

-- ---------------------------------------------------------------------------
-- Client groups: Safe Search, YouTube restrictions, DNS64
-- ---------------------------------------------------------------------------

ALTER TABLE client_groups
    ADD COLUMN safe_search TINYINT(1) NOT NULL DEFAULT 0 AFTER blocking,
    ADD COLUMN youtube ENUM('off','moderate','strict') NOT NULL DEFAULT 'off' AFTER safe_search,
    ADD COLUMN dns64 TINYINT(1) NOT NULL DEFAULT 0 AFTER youtube;

-- ---------------------------------------------------------------------------
-- Dynamic DNS
-- ---------------------------------------------------------------------------

-- TSIG keys that may change records of one zone: RFC 2136 updates (nsupdate, routers, certbot's
-- rfc2136 plugin) through dnsdist, and the dyndns2 HTTP protocol (/nic/update) many routers speak.
CREATE TABLE ddns_keys (
    id            INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    zone_id       INT UNSIGNED  NOT NULL,
    -- The TSIG key name, absolute with the trailing dot.
    name          VARCHAR(253)  NOT NULL,
    algorithm     ENUM('hmac-sha256','hmac-sha512','hmac-sha384','hmac-sha224','hmac-sha1') NOT NULL DEFAULT 'hmac-sha256',
    -- Base64. HMAC needs the secret itself, so it is stored as it is (like the dnsdist and Recursor keys).
    secret        VARCHAR(128)  CHARACTER SET ascii NOT NULL,
    -- Owner names the key may change, relative to the zone ('@', 'home', '*.dyn' for every name below dyn).
    names         JSON          NOT NULL,
    -- Record types it may change.
    types         JSON          NOT NULL,
    enabled       TINYINT(1)    NOT NULL DEFAULT 1,
    comment       VARCHAR(255)  NOT NULL DEFAULT '',
    created_by    VARCHAR(64)   NOT NULL DEFAULT '',
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at  DATETIME      NULL,
    last_used_ip  VARCHAR(45)   NOT NULL DEFAULT '',
    PRIMARY KEY (id),
    UNIQUE KEY uq_ddns_keys_name (name),
    KEY idx_ddns_keys_zone (zone_id),
    CONSTRAINT fk_ddns_keys_zone FOREIGN KEY (zone_id) REFERENCES zones (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- Single sign-on (OpenID Connect, any provider; Settings → Single sign-on)
-- ---------------------------------------------------------------------------

-- Sign-ins on their way through the identity provider: the state sent there, the PKCE verifier and
-- the nonce the ID token must carry. One row per click on the sign-in button, deleted when it comes back.
CREATE TABLE IF NOT EXISTS oidc_logins (
    state       CHAR(43)      NOT NULL,
    verifier    CHAR(86)      NOT NULL,
    nonce       CHAR(43)      NOT NULL,
    ip          VARCHAR(45)   NOT NULL DEFAULT '',
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME      NOT NULL,
    PRIMARY KEY (state),
    KEY idx_oidc_logins_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

-- The ID token of a session started through single sign-on: sign-out can hand it to the provider.
ALTER TABLE sessions ADD COLUMN oidc_id_token TEXT NULL AFTER user_agent;
