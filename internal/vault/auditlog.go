package vault

import (
	"database/sql"

	"kosh/internal/audit"
	"kosh/internal/crypto"
)

// auditKeySnapshot returns a copy of the audit MAC subkey, or nil when the vault is
// locked. Callers must not retain it. A nil return is not an error: session events that
// happen while locked (failed unlock, lockout) still get a chain-only record, because
// an unauthenticated entry is strictly better than no entry.
func (v *Vault) auditKeySnapshot() []byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.audKey == nil {
		return nil
	}
	return append([]byte(nil), v.audKey...)
}

// logAudit appends an audit record in its own transaction, authenticated when the vault
// is unlocked. Use it for session-lifecycle events with no surrounding data mutation.
func (v *Vault) logAudit(action, target string, outcome audit.Outcome, detail string) error {
	key := v.auditKeySnapshot()
	defer crypto.Zero(key)
	return audit.LogKeyed(v.db.SQL(), key, v.actor, action, target, outcome, detail)
}

// logAuditTx appends an audit record inside the caller's transaction, authenticated when
// the vault is unlocked. Use it for state-changing operations so the record commits or
// rolls back atomically with the mutation it describes.
func (v *Vault) logAuditTx(tx *sql.Tx, action, target string, outcome audit.Outcome, detail string) error {
	key := v.auditKeySnapshot()
	defer crypto.Zero(key)
	return audit.LogTxKeyed(tx, key, v.actor, action, target, outcome, detail)
}

// VerifyAuditChain checks the audit log for tampering. When the vault is unlocked it
// performs the full keyed verification (per-record HMACs plus the anchored head), which
// an attacker with database write access cannot defeat without the DEK. When locked it
// falls back to the hash-chain-only walk, which still detects corruption. It returns the
// seq of the first bad record, or 0 when the log is intact.
func (v *Vault) VerifyAuditChain() (int64, error) {
	key := v.auditKeySnapshot()
	defer crypto.Zero(key)
	if key == nil {
		return audit.VerifyChain(v.db.SQL())
	}
	return audit.VerifyChainKeyed(v.db.SQL(), key)
}
