-- DNSOne schema, version 0003: per-client policies (groups), regex rules, allowlist subscriptions.

-- Client groups. Each has its own blocklists and rules; clients are matched by address, the most
-- specific network winning. The built-in Default group holds every client in no other group.
CREATE TABLE client_groups (
    id          INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    name        VARCHAR(64)   NOT NULL,
    description VARCHAR(255)  NOT NULL DEFAULT '',
    -- 0: no ad-blocking at all for these clients (no RPZ is loaded for the group).
    blocking    TINYINT(1)    NOT NULL DEFAULT 1,
    built_in    TINYINT(1)    NOT NULL DEFAULT 0,
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_client_groups_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO client_groups (name, description, blocking, built_in)
VALUES ('Default', 'Every client that is not in another group.', 1, 1);

-- Client addresses and subnets per group, in canonical CIDR form ('192.0.2.0/24', '2001:db8::/48').
CREATE TABLE client_group_networks (
    id          INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    group_id    INT UNSIGNED  NOT NULL,
    network     VARCHAR(49)   NOT NULL,
    comment     VARCHAR(255)  NOT NULL DEFAULT '',
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_client_group_networks_network (network),
    KEY idx_client_group_networks_group (group_id),
    CONSTRAINT fk_client_group_networks_group FOREIGN KEY (group_id) REFERENCES client_groups (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Which blocklists (and allowlists) each group uses.
CREATE TABLE client_group_blocklists (
    group_id     INT UNSIGNED NOT NULL,
    blocklist_id INT UNSIGNED NOT NULL,
    PRIMARY KEY (group_id, blocklist_id),
    KEY idx_client_group_blocklists_list (blocklist_id),
    CONSTRAINT fk_cgb_group FOREIGN KEY (group_id) REFERENCES client_groups (id) ON DELETE CASCADE,
    CONSTRAINT fk_cgb_list FOREIGN KEY (blocklist_id) REFERENCES blocklists (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Existing lists keep applying to everyone.
INSERT INTO client_group_blocklists (group_id, blocklist_id)
SELECT g.id, b.id FROM client_groups g CROSS JOIN blocklists b WHERE g.built_in = 1;

-- Allowlist subscriptions: downloaded lists whose names are never blocked.
ALTER TABLE blocklists ADD COLUMN kind ENUM('block','allow') NOT NULL DEFAULT 'block' AFTER format;

-- Rules: exact names (as before) or regular expressions, for every group (group_id NULL) or one.
-- group_key makes (pattern, group) unique with NULL meaning "all groups"; MySQL forbids CASCADE on
-- a generated column's base column, so deleting a group deletes its rules in the application.
ALTER TABLE rpz_rules
    ADD COLUMN match_type ENUM('exact','regex') NOT NULL DEFAULT 'exact' AFTER pattern,
    ADD COLUMN group_id INT UNSIGNED NULL AFTER target,
    ADD COLUMN group_key INT UNSIGNED AS (IFNULL(group_id, 0)) STORED,
    DROP INDEX uq_rpz_rules_pattern,
    ADD UNIQUE KEY uq_rpz_rules_pattern (pattern, group_key),
    ADD KEY idx_rpz_rules_group (group_id),
    ADD CONSTRAINT fk_rpz_rules_group FOREIGN KEY (group_id) REFERENCES client_groups (id) ON DELETE RESTRICT;
