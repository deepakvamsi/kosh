-- 0009_recovery_kdf_params.sql
--
-- Gives the recovery-key slot its own Argon2id parameters.
--
-- Until now the recovery KDF reused the vault's `kdf_time` / `kdf_memory_kib` /
-- `kdf_threads` columns — the same ones the master-password KEK uses. That coupling was
-- invisible while those values never changed. It stops being invisible the moment the
-- vault can be re-keyed with stronger parameters (first-run calibration, or an explicit
-- "strengthen encryption" action):
--
--   * `GenerateRecoveryKey` derives the RKEK with whatever parameters are stored at that
--     moment, and `RecoverWithKey` re-derives it with whatever is stored LATER. Change the
--     vault's parameters in between and the recovery key silently stops unwrapping the
--     DEK — the one credential whose entire job is to work when nothing else does.
--   * `RecoverWithKey` also wrote `DefaultKDFParams()` back into the vault, which would
--     have downgraded a calibrated vault to the floor on every recovery.
--
-- Separate columns break the coupling: re-keying the master password touches only the
-- `kdf_*` columns, and the recovery slot keeps the parameters its RKEK was actually
-- derived under.
--
-- NULL means "pre-0009 vault": the reader falls back to the shared `kdf_*` columns, which
-- is exactly what such a vault's RKEK was derived with. The columns are populated the next
-- time a recovery key is generated.

ALTER TABLE vault_meta ADD COLUMN recovery_kdf_time INTEGER;
ALTER TABLE vault_meta ADD COLUMN recovery_kdf_memory_kib INTEGER;
ALTER TABLE vault_meta ADD COLUMN recovery_kdf_threads INTEGER;
