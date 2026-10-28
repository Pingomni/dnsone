-- DNSOne schema, version 0010 (1.5.14): zones created by a reseller or customer wait for an administrator before
-- the resolver uses them, so a tenant cannot take over another domain (google.com) for every subscriber.
-- Existing zones are approved; 1.5.13 ignores the column.
ALTER TABLE zones ADD COLUMN approved TINYINT(1) NOT NULL DEFAULT 1;
