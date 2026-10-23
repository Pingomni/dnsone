-- DNSOne schema, version 0002: query visibility.
-- Written by dnsone-querylog from the Recursor's protobuf stream.

-- Recent answers, one row each. Short retention (DNSONE_QUERYLOG_RETENTION_HOURS and
-- DNSONE_QUERYLOG_MAX_ROWS): at ISP scale this table grows by millions of rows a day.
CREATE TABLE query_log (
    id          BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    node        VARCHAR(64)      NOT NULL,
    ts          DATETIME(3)      NOT NULL,
    client      VARCHAR(45)      NOT NULL,
    qname       VARCHAR(253)     NOT NULL,
    qtype       SMALLINT UNSIGNED NOT NULL,
    rcode       TINYINT UNSIGNED NOT NULL,
    -- ok: normal answer. blocked: an RPZ block/redirect trigger matched. allowed: an allow rule matched.
    status      ENUM('ok','blocked','allowed') NOT NULL,
    latency_us  INT UNSIGNED     NULL,
    PRIMARY KEY (id),
    KEY idx_query_log_ts (ts),
    KEY idx_query_log_client (client, id),
    KEY idx_query_log_qname (qname(100), id),
    KEY idx_query_log_status (status, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Hourly counts behind the top lists, kept for weeks. Each minute the collector adds the
-- busiest items of that minute per dimension, so long-tail items are approximate by design.
CREATE TABLE query_stats_hourly (
    hour       DATETIME         NOT NULL,
    dimension  ENUM('domain','blocked','client','client_blocked','qtype','rcode','status') NOT NULL,
    node       VARCHAR(64)      NOT NULL,
    item       VARCHAR(253)     NOT NULL,
    hits       BIGINT UNSIGNED  NOT NULL,
    PRIMARY KEY (hour, dimension, node, item),
    KEY idx_query_stats_dim (dimension, hour)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- Who may see query logs and top lists (personal data): admin and operator.
UPDATE roles SET permissions = JSON_ARRAY_APPEND(permissions, '$', 'queries.view')
 WHERE name IN ('admin', 'operator') AND NOT JSON_CONTAINS(permissions, '"queries.view"');
