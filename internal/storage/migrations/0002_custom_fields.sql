-- 0002_custom_fields.sql
-- Adds a custom_fields column to secrets for user-defined key-value metadata.
-- The column is stored as JSON text (SQLite has no native JSON type but supports
-- json_extract() for queries). Values are never secrets — store only labels,
-- URLs, team names, account IDs, rotation notes, etc.
-- Example value: '{"account_id":"123456","team":"platform","ticket":"SEC-42"}'

ALTER TABLE secrets ADD COLUMN custom_fields TEXT NOT NULL DEFAULT '{}';
