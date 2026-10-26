-- DNSOne schema, version 0009 (1.5): zone transfers to customers' own secondaries, customer quotas,
-- attack protection, the firewall. Every change is additive; 1.4 ignores the new tables and columns.

-- ---------------------------------------------------------------------------
-- Zone transfers to customers' own secondaries
-- ---------------------------------------------------------------------------

-- Addresses allowed to transfer (AXFR/IXFR) one zone through dnsdist on port 53, and the secondaries
-- BIND notifies when it changes. Transfers of a zone not listed here are refused.
CREATE TABLE zone_transfers (
    id           INT UNSIGNED      NOT NULL AUTO_INCREMENT,
    zone_id      INT UNSIGNED      NOT NULL,
    -- An address or a network ('192.0.2.53', '2001:db8::/64').
    address      VARCHAR(49)       NOT NULL,
    -- Send NOTIFY to it when the zone changes (single addresses only).
    notify       TINYINT(1)        NOT NULL DEFAULT 1,
    notify_port  SMALLINT UNSIGNED NOT NULL DEFAULT 53,
    comment      VARCHAR(255)      NOT NULL DEFAULT '',
    created_by   VARCHAR(64)       NOT NULL DEFAULT '',
    created_at   DATETIME          NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_zone_transfers (zone_id, address),
    CONSTRAINT fk_zone_transfers_zone FOREIGN KEY (zone_id) REFERENCES zones (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- The zone's transfer key: with one, BIND transfers the zone only to requests signed with it (TSIG),
-- on top of the address check. NULL: the address alone decides.
ALTER TABLE zones
    ADD COLUMN xfr_key_name VARCHAR(253) NULL AFTER alias_cache,
    ADD COLUMN xfr_key_algorithm ENUM('hmac-sha256','hmac-sha512','hmac-sha384','hmac-sha224','hmac-sha1') NULL AFTER xfr_key_name,
    ADD COLUMN xfr_key_secret VARCHAR(128) CHARACTER SET ascii NULL AFTER xfr_key_algorithm,
    ADD UNIQUE KEY uq_zones_xfr_key (xfr_key_name);

-- ---------------------------------------------------------------------------
-- Customer quotas
-- ---------------------------------------------------------------------------

-- For accounts limited to their own zones (customers, resellers). NULL: no limit.
ALTER TABLE users
    ADD COLUMN max_zones INT UNSIGNED NULL AFTER parent_id,
    ADD COLUMN max_records INT UNSIGNED NULL AFTER max_zones,
    ADD COLUMN api_rate INT UNSIGNED NULL AFTER max_records;

-- API requests per user and minute, for api_rate. Rows older than a few minutes are deleted.
CREATE TABLE api_usage (
    user_id   INT UNSIGNED NOT NULL,
    minute    DATETIME     NOT NULL,
    requests  INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, minute),
    KEY idx_api_usage_minute (minute),
    CONSTRAINT fk_api_usage_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

-- ---------------------------------------------------------------------------
-- Attack protection
-- ---------------------------------------------------------------------------

-- What dnsdist blocked by itself (dynamic blocks), one row per node, target and episode.
CREATE TABLE attack_events (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    node        VARCHAR(64)     NOT NULL,
    -- flood, servfail, nxdomain (a client asking for many names that do not exist), amplification
    -- (large answers to one address), random-subdomain (a domain under a water-torture attack).
    kind        VARCHAR(20)     NOT NULL,
    -- A client network ('198.51.100.7/32') or a domain ('victim.example.').
    target      VARCHAR(253)    NOT NULL,
    reason      VARCHAR(255)    NOT NULL DEFAULT '',
    action      VARCHAR(16)     NOT NULL DEFAULT '',
    first_seen  DATETIME        NOT NULL,
    last_seen   DATETIME        NOT NULL,
    -- Queries blocked during the episode (the highest count dnsdist reported).
    blocks      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    KEY idx_attack_events_seen (last_seen),
    KEY idx_attack_events_target (target, last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Blocks an operator added: queries from a client network are dropped, or queries for a domain
-- (and every name below it) are refused, by dnsdist on every node.
CREATE TABLE protection_blocks (
    id          INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    kind        ENUM('client','domain') NOT NULL,
    value       VARCHAR(253)  NOT NULL,
    reason      VARCHAR(255)  NOT NULL DEFAULT '',
    created_by  VARCHAR(64)   NOT NULL DEFAULT '',
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- NULL: until removed.
    expires_at  DATETIME      NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_protection_blocks (kind, value)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ---------------------------------------------------------------------------
-- Firewall
-- ---------------------------------------------------------------------------

-- Rules of the firewall DNSOne manages (nftables, table inet dnsone), in order. They are a draft until
-- applied: Apply stores a snapshot in settings (firewall.active), which every node loads.
CREATE TABLE firewall_rules (
    id          INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    position    INT UNSIGNED  NOT NULL DEFAULT 0,
    action      ENUM('accept','drop','reject') NOT NULL,
    protocol    ENUM('tcp','udp','tcp+udp','icmp','any') NOT NULL DEFAULT 'tcp',
    -- An address or network; '' for any.
    source      VARCHAR(49)   NOT NULL DEFAULT '',
    -- '22', '80,443', '1000-2000'; '' for every port (and always for icmp and any).
    ports       VARCHAR(64)   NOT NULL DEFAULT '',
    comment     VARCHAR(255)  NOT NULL DEFAULT '',
    enabled     TINYINT(1)    NOT NULL DEFAULT 1,
    created_by  VARCHAR(64)   NOT NULL DEFAULT '',
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- A temporary rule (e.g. a block from Protection); NULL: permanent.
    expires_at  DATETIME      NULL,
    PRIMARY KEY (id),
    KEY idx_firewall_rules_position (position, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- New permissions: the firewall and attack protection.
UPDATE roles SET permissions = JSON_ARRAY_APPEND(permissions, '$', 'protection.view')
 WHERE name IN ('admin', 'operator') AND NOT JSON_CONTAINS(permissions, '"protection.view"');
UPDATE roles SET permissions = JSON_ARRAY_APPEND(permissions, '$', 'protection.manage')
 WHERE name IN ('admin', 'operator') AND NOT JSON_CONTAINS(permissions, '"protection.manage"');
UPDATE roles SET permissions = JSON_ARRAY_APPEND(permissions, '$', 'firewall.manage')
 WHERE name = 'admin' AND NOT JSON_CONTAINS(permissions, '"firewall.manage"');
