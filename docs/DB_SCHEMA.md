# Kosh — Database Schema (v1)

Pure-Go SQLite (`modernc.org/sqlite`, no CGO). Secret **values** are always stored as
AEAD ciphertext (`nonce || ciphertext || tag`). No plaintext secret is ever written.
Timestamps are Unix seconds (UTC). Booleans are `INTEGER` 0/1.

## Migration framework

Migrations live in `internal/storage/migrations/` as ordered `NNNN_name.sql` files and
are applied in a transaction. `schema_migrations(version INTEGER PRIMARY KEY, applied_at)`
tracks what has run. `vault_meta.schema_version` mirrors the latest applied version.

## Tables

### vault_meta (single row, id = 1)
```sql
CREATE TABLE vault_meta (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  kdf            TEXT    NOT NULL,     -- "argon2id"
  kdf_time       INTEGER NOT NULL,
  kdf_memory_kib INTEGER NOT NULL,
  kdf_threads    INTEGER NOT NULL,
  kdf_salt       BLOB    NOT NULL,
  verifier       BLOB    NOT NULL,     -- AEAD verifier blob
  dek_wrapped    BLOB    NOT NULL,     -- DEK wrapped by password KEK
  recovery_salt  BLOB,                 -- for recovery-key KDF (nullable)
  dek_recovery   BLOB,                 -- DEK wrapped by recovery KEK (nullable)
  schema_version INTEGER NOT NULL,
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);
```

### providers
```sql
CREATE TABLE providers (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  key        TEXT NOT NULL UNIQUE,     -- "aws","gcp","openai","anthropic",...,"custom"
  name       TEXT NOT NULL,            -- display name
  category   TEXT NOT NULL,            -- "cloud","ai","vcs","db","platform","custom"
  is_builtin INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
```
Seeded built-ins: AWS, GCP, Azure, OpenAI, Anthropic, Gemini, Grok/xAI, Mistral, Groq,
DeepSeek, OpenRouter, GitHub, GitLab, Bitbucket, Cursor, Replit, Vercel, Cloudflare,
Docker, PostgreSQL, MongoDB, Redis, and Custom.

### folders
```sql
CREATE TABLE folders (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  parent_id  INTEGER REFERENCES folders(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  UNIQUE(parent_id, name)
);
```

### secrets
```sql
CREATE TABLE secrets (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  alias         TEXT NOT NULL UNIQUE,        -- "OPENAI_DEV","AWS_PROD","GITHUB_DEV"
  provider_id   INTEGER NOT NULL REFERENCES providers(id),
  environment   TEXT NOT NULL CHECK (environment IN ('dev','qa','staging','prod')),
  folder_id     INTEGER REFERENCES folders(id) ON DELETE SET NULL,
  description   TEXT,
  value_enc     BLOB NOT NULL,               -- nonce||ciphertext||tag (never plaintext)
  value_hash    BLOB NOT NULL,               -- HMAC/keyed hash for duplicate detection (not reversible)
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  last_used_at  INTEGER,                      -- for "unused" detection
  expires_at    INTEGER,                      -- rotation/expiry tracking (nullable)
  rotation_days INTEGER,                      -- recommended rotation interval (nullable)
  is_archived   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_secrets_provider ON secrets(provider_id);
CREATE INDEX idx_secrets_env      ON secrets(environment);
CREATE INDEX idx_secrets_expires  ON secrets(expires_at);
CREATE INDEX idx_secrets_valhash  ON secrets(value_hash);
```
`value_hash` is a keyed hash (HMAC with a vault-scoped subkey) so we can detect
**duplicate** credentials without ever comparing plaintext or enabling offline
dictionary attacks on the hashes.

### tags & secret_tags
```sql
CREATE TABLE tags (
  id   INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE secret_tags (
  secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  tag_id    INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (secret_id, tag_id)
);
```

### audit_log (append-only, hash-chained)
```sql
CREATE TABLE audit_log (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  actor      TEXT NOT NULL,        -- always the in-app UI session, e.g. "ui"
  action     TEXT NOT NULL,        -- "unlock","reveal","copy","create","update","delete","backup","autolock"
  target     TEXT,                 -- alias or resource, never the secret value
  outcome    TEXT NOT NULL,        -- "allow" | "deny"
  detail     TEXT,                 -- non-secret context (reason for deny, etc.)
  prev_hash  BLOB NOT NULL,
  hash       BLOB NOT NULL         -- SHA-256(prev_hash || canonical(record))
);
```

### settings (key/value, non-secret app config)
```sql
CREATE TABLE settings (
  key   TEXT PRIMARY KEY,          -- "theme","autolock_seconds","clipboard_clear_seconds","mcp_enabled"
  value TEXT NOT NULL
);
```

## Notes
- No table stores plaintext secrets or the master password.
- `value_enc` and all backup blobs are AEAD-protected.
- Foreign keys are enforced (`PRAGMA foreign_keys=ON`); journaling uses WAL.
