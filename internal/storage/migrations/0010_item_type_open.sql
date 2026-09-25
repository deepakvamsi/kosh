-- 0010_item_type_open.sql
--
-- Removes the CHECK constraint on secrets.item_type so new item types can be added
-- without rebuilding the table each time. This release adds 'file' (encrypted file
-- storage), and more types are expected. The authoritative validator is the Go layer
-- (vault.validItemType), which every write already passes through; the column-level
-- CHECK was redundant defense-in-depth over NON-secret metadata, not a control over any
-- secret material. Dropping it once is preferable to a full-table rebuild per new type.
--
-- SQLite cannot drop a column CHECK in place, so the table is rebuilt. The rebuild is
-- FK-safe WITHOUT toggling foreign_keys (impossible inside a migration transaction):
-- secret_tags is the only table with a foreign key into secrets, so it is backed up and
-- dropped first, the table is rebuilt, and secret_tags is recreated and restored. The
-- whole migration runs in one transaction (see applyMigration) — all-or-nothing. No
-- secret material is touched: value_enc / value_hash blobs are copied verbatim.
--
-- Column set below is the schema after 0001–0004 (0007 rebuilt it with a widened CHECK;
-- 0006 dropped secret_history). item_type keeps its NOT NULL DEFAULT 'api_key' but no
-- longer carries a CHECK.

CREATE TABLE _secret_tags_backup AS SELECT * FROM secret_tags;
DROP TABLE secret_tags;

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
  item_type     TEXT NOT NULL DEFAULT 'api_key',
  is_favorite   INTEGER NOT NULL DEFAULT 0,
  totp_enc      BLOB
);

INSERT INTO secrets_new (id,alias,provider_id,environment,folder_id,description,value_enc,value_hash,created_at,updated_at,last_used_at,expires_at,rotation_days,is_archived,custom_fields,item_type,is_favorite,totp_enc)
  SELECT id,alias,provider_id,environment,folder_id,description,value_enc,value_hash,created_at,updated_at,last_used_at,expires_at,rotation_days,is_archived,custom_fields,item_type,is_favorite,totp_enc FROM secrets;

DROP TABLE secrets;
ALTER TABLE secrets_new RENAME TO secrets;

CREATE INDEX idx_secrets_provider  ON secrets(provider_id);
CREATE INDEX idx_secrets_env       ON secrets(environment);
CREATE INDEX idx_secrets_expires   ON secrets(expires_at);
CREATE INDEX idx_secrets_valhash   ON secrets(value_hash);
CREATE INDEX idx_secrets_item_type ON secrets(item_type);
CREATE INDEX idx_secrets_favorite  ON secrets(is_favorite);

CREATE TABLE secret_tags (
  secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  tag_id    INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
  PRIMARY KEY (secret_id, tag_id)
);
INSERT INTO secret_tags (secret_id,tag_id) SELECT secret_id,tag_id FROM _secret_tags_backup;
DROP TABLE _secret_tags_backup;
