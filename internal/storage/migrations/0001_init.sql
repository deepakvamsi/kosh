-- 0001_init.sql — Kosh schema v1
-- No table stores plaintext secrets or the master password.

CREATE TABLE vault_meta (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  kdf            TEXT    NOT NULL,
  kdf_time       INTEGER NOT NULL,
  kdf_memory_kib INTEGER NOT NULL,
  kdf_threads    INTEGER NOT NULL,
  kdf_salt       BLOB    NOT NULL,
  verifier       BLOB    NOT NULL,
  dek_wrapped    BLOB    NOT NULL,
  recovery_salt  BLOB,
  dek_recovery   BLOB,
  schema_version INTEGER NOT NULL,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

CREATE TABLE providers (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  key        TEXT NOT NULL UNIQUE,
  name       TEXT NOT NULL,
  category   TEXT NOT NULL,
  is_builtin INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE folders (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  parent_id  INTEGER REFERENCES folders(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  UNIQUE(parent_id, name)
);

CREATE TABLE secrets (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  alias         TEXT NOT NULL UNIQUE,
  provider_id   INTEGER NOT NULL REFERENCES providers(id),
  environment   TEXT NOT NULL CHECK (environment IN ('dev','qa','staging','prod')),
  folder_id     INTEGER REFERENCES folders(id) ON DELETE SET NULL,
  description   TEXT,
  value_enc     BLOB NOT NULL,
  value_hash    BLOB NOT NULL,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  last_used_at  INTEGER,
  expires_at    INTEGER,
  rotation_days INTEGER,
  is_archived   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_secrets_provider ON secrets(provider_id);
CREATE INDEX idx_secrets_env      ON secrets(environment);
CREATE INDEX idx_secrets_expires  ON secrets(expires_at);
CREATE INDEX idx_secrets_valhash  ON secrets(value_hash);

CREATE TABLE tags (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE secret_tags (
  secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  tag_id    INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (secret_id, tag_id)
);

CREATE TABLE audit_log (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  actor      TEXT NOT NULL,
  action     TEXT NOT NULL,
  target     TEXT,
  outcome    TEXT NOT NULL,
  detail     TEXT,
  prev_hash  BLOB NOT NULL,
  hash       BLOB NOT NULL
);

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
