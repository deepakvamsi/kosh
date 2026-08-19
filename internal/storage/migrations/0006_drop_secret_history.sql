-- 0006_drop_secret_history.sql
--
-- Removes the value-history feature entirely. Previous encrypted values were
-- retained in secret_history on every UpdateValue so a user could view an
-- earlier value; that feature has been removed by product decision.
--
-- Dropping the table PURGES all retained previous values on upgrade. This is a
-- data-minimization win: the vault no longer keeps superseded secret material
-- around after a rotation. Idempotent — safe on databases that never had the
-- table (fresh installs where 0004/0005 created it, and any future state).
--
-- The current secrets.value_enc is untouched; only historical copies are removed.

DROP INDEX IF EXISTS idx_history_secret;
DROP TABLE IF EXISTS secret_history;
