-- 0003_item_type.sql
-- Introduces first-class item types so the vault can hold logins (username + password)
-- and secure notes alongside raw API keys — the 1Password/Bitwarden model.
--
-- item_type is NON-SECRET metadata (like provider/environment), so it is stored in the
-- clear to allow filtering and type-aware UI without decryption. The sensitive payload
-- for every type still lives ONLY in the encrypted value_enc blob:
--   api_key      -> value_enc = raw key bytes            (unchanged; existing rows)
--   login        -> value_enc = JSON {"username","password"}
--   secure_note  -> value_enc = note text
--
-- Existing rows default to 'api_key', so this migration is fully backward compatible.

ALTER TABLE secrets ADD COLUMN item_type TEXT NOT NULL DEFAULT 'api_key'
  CHECK (item_type IN ('api_key','login','secure_note'));

CREATE INDEX idx_secrets_item_type ON secrets(item_type);
