-- 0007_keypair_item_type.sql
--
-- Adds 'keypair' to the item_type CHECK on secrets so an access-key / secret-key
-- pair can live as ONE encrypted entry (value_enc = JSON {accessKey,secretKey}),
-- mirroring how 'login' stores {username,password}. Previously a key pair was two
-- separate secrets linked only by an alias naming convention.
--
-- SQLite cannot alter a column-level CHECK in place, so the table is rebuilt. The
-- rebuild is FK-safe WITHOUT toggling foreign_keys (which is not possible inside a
-- migration transaction): secret_tags is the only table with a foreign key into
-- secrets, so it is backed up and dropped first (removing the inbound reference),
-- the table is rebuilt with the widened CHECK, and secret_tags is recreated and
-- restored. The whole migration runs in one transaction (see applyMigration), so it
-- is all-or-nothing — a failure rolls back to the pre-migration schema and data.
--
-- The full column set below is the schema after migrations 0001–0004 (0005 only
-- re-adds those same columns on older DBs; 0006 dropped secret_history). No secret
-- material is touched: value_enc / value_hash blobs are copied verbatim.

-- 1. Preserve tag associations, then drop the only child FK into secrets.
CREATE TABLE _secret_tags_backup AS SELECT * FROM secret_tags;
DROP TABLE secret_tags;

-- 2. Rebuild secrets with item_type CHECK widened to include 'keypair'.
CREATE TABLE secrets_new (
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
  is_archived   INTEGER NOT NULL DEFAULT 0,
  custom_fields TEXT NOT NULL DEFAULT '{}',
  item_type     TEXT NOT NULL DEFAULT 'api_key' CHECK (item_type IN ('api_key','login','secure_note','keypair')),
  is_favorite   INTEGER NOT NULL DEFAULT 0,
  totp_enc      BLOB
);

INSERT INTO secrets_new (id,alias,provider_id,environment,folder_id,description,value_enc,value_hash,created_at,updated_at,last_used_at,expires_at,rotation_days,is_archived,custom_fields,item_type,is_favorite,totp_enc)
  SELECT id,alias,provider_id,environment,folder_id,description,value_enc,value_hash,created_at,updated_at,last_used_at,expires_at,rotation_days,is_archived,custom_fields,item_type,is_favorite,totp_enc FROM secrets;

DROP TABLE secrets;
ALTER TABLE secrets_new RENAME TO secrets;

-- 3. Recreate the indexes that lived on the old secrets table (0001/0003/0004).
CREATE INDEX idx_secrets_provider  ON secrets(provider_id);
CREATE INDEX idx_secrets_env       ON secrets(environment);
CREATE INDEX idx_secrets_expires   ON secrets(expires_at);
CREATE INDEX idx_secrets_valhash   ON secrets(value_hash);
CREATE INDEX idx_secrets_item_type ON secrets(item_type);
CREATE INDEX idx_secrets_favorite  ON secrets(is_favorite);

-- 4. Recreate secret_tags (FK back into the rebuilt secrets) and restore rows.
CREATE TABLE secret_tags (
  secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  tag_id    INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (secret_id, tag_id)
);
INSERT INTO secret_tags (secret_id,tag_id) SELECT secret_id,tag_id FROM _secret_tags_backup;
DROP TABLE _secret_tags_backup;
