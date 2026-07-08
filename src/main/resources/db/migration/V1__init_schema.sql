CREATE TABLE users (
                       id         BIGSERIAL PRIMARY KEY,
                       email      VARCHAR(255) NOT NULL UNIQUE,
                       password_hash VARCHAR(255) NOT NULL,
                       salt       VARCHAR(255) NOT NULL,
                       created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE vault_entries (
                               id                BIGSERIAL PRIMARY KEY,
                               user_id           BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                               site              VARCHAR(255) NOT NULL,
                               login             VARCHAR(255) NOT NULL,
                               encrypted_password TEXT NOT NULL,
                               iv                VARCHAR(255) NOT NULL,
                               created_at        TIMESTAMP NOT NULL DEFAULT NOW(),
                               updated_at        TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vault_entries_user_id ON vault_entries(user_id);