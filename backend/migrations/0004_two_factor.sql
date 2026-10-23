-- DNSOne schema, version 0004: two-factor sign-in (TOTP) and app passwords for the API.

ALTER TABLE users
    -- Base32 TOTP secret. Set while enrolling; totp_enabled turns it on once a code was confirmed.
    ADD COLUMN totp_secret    VARCHAR(64)     NULL AFTER password_hash,
    ADD COLUMN totp_enabled   TINYINT(1)      NOT NULL DEFAULT 0 AFTER totp_secret,
    -- Last accepted 30-second step: a code is never accepted twice.
    ADD COLUMN totp_last_step BIGINT UNSIGNED NULL AFTER totp_enabled,
    -- SHA-256 hashes of unused one-time recovery codes.
    ADD COLUMN recovery_codes JSON            NULL AFTER totp_last_step;

-- Sign-in that passed the password check and waits for the second factor.
CREATE TABLE auth_challenges (
    id          CHAR(64)      NOT NULL,
    user_id     INT UNSIGNED  NOT NULL,
    attempts    INT UNSIGNED  NOT NULL DEFAULT 0,
    ip          VARCHAR(45)   NOT NULL DEFAULT '',
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at  DATETIME      NOT NULL,
    PRIMARY KEY (id),
    KEY idx_auth_challenges_expires (expires_at),
    CONSTRAINT fk_auth_challenges_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=ascii COLLATE=ascii_bin;

-- App passwords: bearer tokens for scripts and monitoring, with the owner's role (or read-only).
CREATE TABLE api_tokens (
    id           INT UNSIGNED  NOT NULL AUTO_INCREMENT,
    user_id      INT UNSIGNED  NOT NULL,
    name         VARCHAR(64)   NOT NULL,
    -- SHA-256 of the token; the token itself is shown once, at creation.
    token_hash   CHAR(64)      CHARACTER SET ascii NOT NULL,
    prefix       VARCHAR(12)   CHARACTER SET ascii NOT NULL,
    read_only    TINYINT(1)    NOT NULL DEFAULT 0,
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME      NULL,
    last_used_ip VARCHAR(45)   NOT NULL DEFAULT '',
    expires_at   DATETIME      NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_api_tokens_hash (token_hash),
    KEY idx_api_tokens_user (user_id),
    CONSTRAINT fk_api_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
