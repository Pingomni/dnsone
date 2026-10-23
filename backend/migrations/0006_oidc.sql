-- DNSOne schema, version 0006: single sign-on through Keycloak (OpenID Connect). Removed again in
-- 1.3.1 (0007 drops both); kept so databases that applied it and new ones end up the same.

-- Sign-ins on their way through Keycloak: the state sent there, the PKCE verifier and the nonce
-- the ID token must carry. One row per click on "Sign in with SSO", deleted when it comes back.
CREATE TABLE oidc_logins (
    state       CHAR(43)      NOT NULL,
    verifier    CHAR(86)      NOT NULL,
    nonce       CHAR(43)      NOT NULL,
    ip          VARCHAR(45)   NOT NULL DEFAULT '',
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME      NOT NULL,
    PRIMARY KEY (state),
    KEY idx_oidc_logins_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

-- The ID token of a session started through SSO: sign-out hands it to Keycloak to end its session too.
ALTER TABLE sessions ADD COLUMN oidc_id_token TEXT NULL AFTER user_agent;
