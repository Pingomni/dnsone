-- DNSOne schema, version 0001 (MySQL 8.0, InnoDB, utf8mb4).
-- Applied by `dnsone-ctl migrate`, which records each file in schema_migrations.
-- All timestamps are UTC: the application sets time_zone = '+00:00' on every connection.

-- ---------------------------------------------------------------------------
-- Operators
-- ---------------------------------------------------------------------------

CREATE TABLE roles (
    id          INT UNSIGNED     NOT NULL AUTO_INCREMENT,
    name        VARCHAR(32)      NOT NULL,
    description VARCHAR(255)     NOT NULL DEFAULT '',
    permissions JSON             NOT NULL,
    built_in    TINYINT(1)       NOT NULL DEFAULT 0,
    created_at  DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME         NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_roles_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE users (
    id             INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    username       VARCHAR(64)   NOT NULL,
    name           VARCHAR(128)  NOT NULL DEFAULT '',
    email          VARCHAR(254)  NOT NULL DEFAULT '',
    -- NULL for single-sign-on users, who never sign in with a local password.
    password_hash  VARCHAR(255)  NULL,
    role_id        INT UNSIGNED  NOT NULL,
    enabled        TINYINT(1)    NOT NULL DEFAULT 1,
    -- 'local' today; 'oidc' is reserved for Keycloak (external_id holds the token's `sub`).
    auth_source    ENUM('local','oidc') NOT NULL DEFAULT 'local',
    external_id    VARCHAR(255)  NULL,
    failed_logins  INT UNSIGNED  NOT NULL DEFAULT 0,
    locked_until   DATETIME      NULL,
    last_login_at  DATETIME      NULL,
    created_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_username (username),
    UNIQUE KEY uq_users_external (auth_source, external_id),
    KEY idx_users_role (role_id),
    CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Server-side sessions: the cookie holds a random token, this table holds its SHA-256.
-- Kept in MySQL so any API node can serve any request once Phase 2 adds more nodes.
CREATE TABLE sessions (
    id           CHAR(64)      NOT NULL,
    user_id      INT UNSIGNED  NOT NULL,
    csrf_token   CHAR(43)      NOT NULL,
    ip           VARCHAR(45)   NOT NULL DEFAULT '',
    user_agent   VARCHAR(255)  NOT NULL DEFAULT '',
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   DATETIME      NOT NULL,
    PRIMARY KEY (id),
    KEY idx_sessions_user (user_id),
    KEY idx_sessions_expires (expires_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

-- ---------------------------------------------------------------------------
-- Authoritative zones
-- ---------------------------------------------------------------------------

CREATE TABLE zones (
    id                 INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    -- Lower-case, A-label (punycode) form, no trailing dot.
    name               VARCHAR(253)  NOT NULL,
    description        VARCHAR(255)  NOT NULL DEFAULT '',
    -- YYYYMMDDnn. The serial of the last file written; the generator advances it on each publish.
    serial             INT UNSIGNED  NOT NULL DEFAULT 0,
    default_ttl        INT UNSIGNED  NOT NULL DEFAULT 3600,
    soa_mname          VARCHAR(253)  NOT NULL,
    soa_rname          VARCHAR(253)  NOT NULL,
    soa_refresh        INT UNSIGNED  NOT NULL DEFAULT 7200,
    soa_retry          INT UNSIGNED  NOT NULL DEFAULT 1800,
    soa_expire         INT UNSIGNED  NOT NULL DEFAULT 1209600,
    soa_minimum        INT UNSIGNED  NOT NULL DEFAULT 300,
    -- active: served by BIND. disabled: removed from BIND, data kept.
    status             ENUM('active','disabled') NOT NULL DEFAULT 'active',
    -- Bumped by every change to the zone or its records; the generator publishes when
    -- revision <> published_revision, so a change made during a publish is never lost.
    revision           INT UNSIGNED  NOT NULL DEFAULT 1,
    published_revision INT UNSIGNED  NOT NULL DEFAULT 0,
    publish_state      ENUM('pending','published','error') NOT NULL DEFAULT 'pending',
    published_serial   INT UNSIGNED  NULL,
    published_at       DATETIME      NULL,
    last_error         TEXT          NULL,
    created_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_zones_name (name),
    KEY idx_zones_status (status, publish_state),
    CONSTRAINT ck_zones_ttl CHECK (default_ttl BETWEEN 60 AND 604800)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE records (
    id          BIGINT UNSIGNED   NOT NULL AUTO_INCREMENT,
    zone_id     INT UNSIGNED      NOT NULL,
    -- Owner name relative to the zone: '@' for the apex, 'www', '_dmarc', '*.dev'.
    name        VARCHAR(253)      NOT NULL,
    type        ENUM('A','AAAA','CNAME','MX','TXT','NS','SRV','CAA','PTR') NOT NULL,
    -- Normalised RDATA without the priority: an address, an absolute name with trailing dot,
    -- the TXT text (unquoted), 'weight port target.' for SRV, 'flags tag "value"' for CAA.
    value       VARCHAR(4000)     NOT NULL,
    -- NULL means the zone's default_ttl.
    ttl         INT UNSIGNED      NULL,
    -- MX preference and SRV priority; NULL for every other type.
    priority    SMALLINT UNSIGNED NULL,
    disabled    TINYINT(1)        NOT NULL DEFAULT 0,
    comment     VARCHAR(255)      NOT NULL DEFAULT '',
    -- Identity of the record set member, so the same RR cannot be entered twice.
    rr_hash     BINARY(16) AS (UNHEX(MD5(CONCAT_WS('|', name, type, IFNULL(priority, ''), value)))) STORED,
    created_at  DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    -- Serves both "records of a zone" (zone_id prefix) and "this name/type in a zone".
    KEY idx_records_zone_name_type (zone_id, name, type),
    UNIQUE KEY uq_records_rr (zone_id, rr_hash),
    KEY idx_records_type (zone_id, type),
    CONSTRAINT fk_records_zone FOREIGN KEY (zone_id) REFERENCES zones (id) ON DELETE CASCADE,
    CONSTRAINT ck_records_ttl CHECK (ttl IS NULL OR ttl BETWEEN 60 AND 604800)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- Ad-blocking (RPZ)
-- ---------------------------------------------------------------------------

CREATE TABLE rpz_rules (
    id          INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    -- 'example.com' (that name only) or '*.example.com' (every name below it).
    pattern     VARCHAR(253)  NOT NULL,
    -- block: the default policy. allow: whitelist, overrides every blocklist.
    -- nxdomain / nodata / redirect: this rule's own response (redirect uses target).
    action      ENUM('block','allow','nxdomain','nodata','redirect') NOT NULL,
    target      VARCHAR(253)  NULL,
    source      VARCHAR(64)   NOT NULL DEFAULT 'manual',
    enabled     TINYINT(1)    NOT NULL DEFAULT 1,
    comment     VARCHAR(255)  NOT NULL DEFAULT '',
    created_by  VARCHAR(64)   NOT NULL DEFAULT '',
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_rpz_rules_pattern (pattern),
    KEY idx_rpz_rules_enabled_action (enabled, action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE blocklists (
    id            INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    name          VARCHAR(128)  NOT NULL,
    url           VARCHAR(2048) NOT NULL,
    format        ENUM('auto','hosts','domains','adblock') NOT NULL DEFAULT 'auto',
    enabled       TINYINT(1)    NOT NULL DEFAULT 1,
    -- Last time new content was fetched and parsed successfully.
    last_updated  DATETIME      NULL,
    last_checked  DATETIME      NULL,
    last_status   ENUM('never','ok','not_modified','error') NOT NULL DEFAULT 'never',
    last_error    VARCHAR(1024) NULL,
    domain_count  INT UNSIGNED  NOT NULL DEFAULT 0,
    etag          VARCHAR(255)  NULL,
    last_modified VARCHAR(64)   NULL,
    content_sha256 CHAR(64)     NULL,
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_blocklists_name (name),
    KEY idx_blocklists_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- Audit, settings, metrics
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor        VARCHAR(64)     NOT NULL,
    action       VARCHAR(64)     NOT NULL,
    entity       VARCHAR(32)     NOT NULL,
    entity_id    VARCHAR(64)     NOT NULL DEFAULT '',
    payload_json JSON            NULL,
    ip           VARCHAR(45)     NOT NULL DEFAULT '',
    created_at   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    KEY idx_audit_created (created_at),
    KEY idx_audit_entity (entity, entity_id),
    KEY idx_audit_actor (actor, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Small key/value store for runtime settings (RPZ policy, RPZ publish state).
CREATE TABLE settings (
    name        VARCHAR(64) NOT NULL,
    value       JSON        NOT NULL,
    updated_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Raw counters read from dnsdist and the Recursor once a minute, per node.
-- Rates and 24-hour totals are differences between samples.
CREATE TABLE stats_samples (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    node          VARCHAR(64)     NOT NULL,
    sampled_at    DATETIME        NOT NULL,
    queries       BIGINT UNSIGNED NULL,
    blocked       BIGINT UNSIGNED NULL,
    cache_hits    BIGINT UNSIGNED NULL,
    cache_misses  BIGINT UNSIGNED NULL,
    servfail      BIGINT UNSIGNED NULL,
    dropped       BIGINT UNSIGNED NULL,
    PRIMARY KEY (id),
    KEY idx_stats_node_time (node, sampled_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- Seed data
-- ---------------------------------------------------------------------------

INSERT INTO roles (name, description, permissions, built_in) VALUES
('admin', 'Full access, including users and system settings.',
 JSON_ARRAY('dashboard.view','zones.view','zones.manage','rpz.view','rpz.manage','audit.view','users.manage','system.manage'), 1),
('operator', 'Manages zones, records, blocklists and RPZ rules.',
 JSON_ARRAY('dashboard.view','zones.view','zones.manage','rpz.view','rpz.manage','audit.view'), 1),
('viewer', 'Read-only access to zones, ad-blocking and statistics.',
 JSON_ARRAY('dashboard.view','zones.view','rpz.view'), 1);

INSERT INTO settings (name, value) VALUES
('rpz.policy', JSON_OBJECT('action', 'nxdomain', 'walled_garden_target', '', 'block_subdomains', TRUE)),
('rpz.state', JSON_OBJECT('serial', 0, 'state', 'never', 'built_at', NULL, 'entries', 0, 'error', NULL));
