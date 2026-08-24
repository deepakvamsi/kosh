-- 0008_audit_mac.sql
--
-- Makes the audit log tamper-EVIDENT against an adversary, not just against accidental
-- corruption.
--
-- Before this migration the chain was hash = SHA-256(prev_hash || record) with no
-- secret involved. Anyone able to write to vault.db could delete or edit a record and
-- simply recompute every hash from that point forward; VerifyChain would then report a
-- perfectly intact chain. The chain detected corruption, not tampering.
--
-- Two additions close that:
--
--   audit_log.mac      HMAC-SHA256(audit-subkey, hash) for records written while the
--                      vault was unlocked. The subkey is derived from the DEK, so it
--                      exists only in memory and only after a correct master password.
--                      Because `hash` already covers prev_hash and the record's own
--                      fields, a MAC over it pins both content and chain position.
--                      NULL is legitimate: session events logged while locked (failed
--                      unlock, lockout) have no key available. Those records are still
--                      hash-chained.
--
--   vault_meta.audit_head_seq / audit_head_mac
--                      HMAC-SHA256(audit-subkey, seq || hash) of the newest keyed
--                      record, rewritten on every keyed append. This anchors the head,
--                      so lopping records off the end — the one edit a per-record MAC
--                      cannot see — is detectable too.
--
-- Existing rows keep mac = NULL and are verified chain-only, so upgrading an existing
-- vault neither fails nor retroactively claims protection it does not have.

ALTER TABLE audit_log ADD COLUMN mac BLOB;

ALTER TABLE vault_meta ADD COLUMN audit_head_seq INTEGER;
ALTER TABLE vault_meta ADD COLUMN audit_head_mac BLOB;
