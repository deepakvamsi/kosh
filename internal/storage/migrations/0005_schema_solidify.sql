-- 0005_schema_solidify.sql
--
-- Schema solidification guard — runs on every existing vault.db that was
-- created before any of migrations 0002/0003/0004 were applied (i.e. databases
-- built from an older binary that did not include those migration files yet).
--
-- The new migrate engine (applyMigration) silently ignores
-- "duplicate column name" errors on ALTER TABLE … ADD COLUMN, so every
-- statement here is safe to execute against a fully-up-to-date database.
-- On a fresh database all of these columns already exist (added by 0002–0004)
-- and every ALTER is a no-op.
--
-- This migration MUST be the last one applied. New feature migrations should
-- continue the numeric sequence (0006, 0007, …) rather than editing this file.

-- ── 0002 columns ─────────────────────────────────────────────────────────────
-- custom_fields: user-defined JSON key-value metadata per secret.
ALTER TABLE secrets ADD COLUMN custom_fields TEXT NOT NULL DEFAULT '{}';

-- ── 0003 columns ─────────────────────────────────────────────────────────────
-- item_type: distinguishes api_key / login / secure_note payloads.
ALTER TABLE secrets ADD COLUMN item_type TEXT NOT NULL DEFAULT 'api_key'
  CHECK (item_type IN ('api_key','login','secure_note'));

-- ── 0004 columns ─────────────────────────────────────────────────────────────
-- is_favorite: pin a secret to the top of the list.
ALTER TABLE secrets ADD COLUMN is_favorite INTEGER NOT NULL DEFAULT 0;

-- totp_enc: optional encrypted TOTP seed for 2FA code generation.
ALTER TABLE secrets ADD COLUMN totp_enc BLOB;

-- secret_history table: retained previous encrypted values on every UpdateValue.
CREATE TABLE IF NOT EXISTS secret_history (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  secret_id  INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  value_enc  BLOB NOT NULL,
  value_hash BLOB NOT NULL,
  changed_at INTEGER NOT NULL
);

-- ── Indexes (CREATE INDEX IF NOT EXISTS is always safe) ──────────────────────
CREATE INDEX IF NOT EXISTS idx_secrets_item_type ON secrets(item_type);
CREATE INDEX IF NOT EXISTS idx_secrets_favorite  ON secrets(is_favorite);
CREATE INDEX IF NOT EXISTS idx_history_secret    ON secret_history(secret_id);
