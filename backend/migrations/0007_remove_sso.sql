-- DNSOne schema, version 0007: single sign-on (Keycloak) removed. DNSOne's own sign-in is the only one.

DROP TABLE oidc_logins;

ALTER TABLE sessions DROP COLUMN oidc_id_token;

-- Accounts that had been moved to Keycloak are DNSOne accounts again. Those without a DNSOne
-- password need a new one: Settings -> Users -> Edit, or dnsone-ctl create-admin NAME.
UPDATE users SET auth_source = 'local', external_id = NULL WHERE auth_source = 'oidc';
