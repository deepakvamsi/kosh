-- 0004_totp_favorites_history.sql
-- Batch B features:
--   * is_favorite  — pin a secret to the top of the list (non-secret flag).
--   * totp_enc     — an OPTIONAL, ENCRYPTED TOTP seed so Kosh can generate 2FA codes
--                    locally. Like value_enc it holds only ciphertext (nonce||ct||tag),
--                    bound to the row via associated data; the seed is never in the clear.
--   * secret_history — previous encrypted values retained when a secret's value changes,
--                    so a user can view/restore an earlier value. Ciphertext only.

ALTER TABLE secrets ADD COLUMN is_favorite INTEGER NOT NULL DEFAULT 0;
ALTER TABLE secrets ADD COLUMN totp_enc BLOB;
CREATE INDEX idx_secrets_favorite ON secrets(is_favorite);

CREATE TABLE secret_history (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  secret_id  INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  value_enc  BLOB NOT NULL,
  value_hash BLOB NOT NULL,
  changed_at INTEGER NOT NULL
);
CREATE INDEX idx_history_secret ON secret_history(secret_id);
