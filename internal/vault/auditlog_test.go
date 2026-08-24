package vault

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"kosh/internal/audit"
)

// auditChainHashForTest reimplements the audit package's unexported chain hash so this
// test can forge a repaired chain the way an attacker with database access would. Being
// an independent implementation, it also pins the canonical encoding: if audit's
// encoding changes without thought, TestVaultDetectsRewrittenAuditLog starts failing
// for the right reason.
func auditChainHashForTest(prev []byte, ts int64, actor, action, target string, outcome audit.Outcome, detail string) []byte {
	var buf []byte
	appendField := func(s string) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(s)))
		buf = append(buf, l[:]...)
		buf = append(buf, s...)
	}
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], uint64(ts))
	buf = append(buf, tsb[:]...)
	appendField(actor)
	appendField(action)
	appendField(target)
	appendField(string(outcome))
	appendField(detail)

	h := sha256.New()
	h.Write(prev)
	h.Write(buf)
	return h.Sum(nil)
}

// countMACs returns how many audit records are authenticated vs chain-only.
func countMACs(t *testing.T, v *Vault) (keyed, unkeyed int) {
	t.Helper()
	if err := v.DB().SQL().QueryRow(
		`SELECT count(*) FILTER (WHERE mac IS NOT NULL), count(*) FILTER (WHERE mac IS NULL) FROM audit_log`,
	).Scan(&keyed, &unkeyed); err != nil {
		t.Fatalf("count macs: %v", err)
	}
	return keyed, unkeyed
}

// Every record written while the vault is unlocked must be authenticated — including
// the "init" record, which is written before the DEK is installed and so was the easy
// one to get wrong.
func TestUnlockedOperationsWriteKeyedRecords(t *testing.T) {
	v := newInitedVault(t)

	keyed, unkeyed := countMACs(t, v)
	if keyed != 1 || unkeyed != 0 {
		t.Fatalf("after Init: keyed=%d unkeyed=%d, want 1 and 0", keyed, unkeyed)
	}

	if _, err := v.AddSecret(AddSecretInput{
		Alias: "K1", ProviderKey: "github", Environment: Dev, Value: []byte("v"),
	}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	if _, err := v.Reveal("K1"); err != nil {
		t.Fatalf("Reveal: %v", err)
	}

	keyed, unkeyed = countMACs(t, v)
	if unkeyed != 0 {
		t.Fatalf("%d unauthenticated records written while unlocked, want 0", unkeyed)
	}
	if keyed < 3 {
		t.Fatalf("keyed records = %d, want at least 3 (init, create, reveal)", keyed)
	}

	if bad, err := v.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("VerifyAuditChain: bad=%d err=%v", bad, err)
	}
}

// Failed unlocks happen with no DEK in memory, so they cannot be authenticated. They
// must still be logged — an unauthenticated record beats no record — and must not make
// verification fail.
func TestLockedStateEventsAreLoggedUnkeyed(t *testing.T) {
	v := newInitedVault(t)
	v.Lock()

	if err := v.Unlock([]byte("wrong")); err == nil {
		t.Fatal("Unlock with the wrong password succeeded")
	}

	_, unkeyed := countMACs(t, v)
	if unkeyed == 0 {
		t.Fatal("a failed unlock left no audit record")
	}

	// Locked: verification degrades to the chain walk and must still be clean.
	if bad, err := v.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("locked VerifyAuditChain: bad=%d err=%v", bad, err)
	}

	// Unlocked: the keyed check must also pass, with the unkeyed record interleaved.
	if err := v.Unlock([]byte("pw")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if bad, err := v.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("keyed VerifyAuditChain: bad=%d err=%v", bad, err)
	}
}

// The audit subkey is derived from the DEK, so it must survive a lock/unlock cycle —
// otherwise every record written before the lock would fail verification afterwards.
func TestAuditKeySurvivesLockUnlock(t *testing.T) {
	v := newInitedVault(t)
	if _, err := v.AddSecret(AddSecretInput{
		Alias: "K1", ProviderKey: "github", Environment: Dev, Value: []byte("v"),
	}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	v.Lock()
	if err := v.Unlock([]byte("pw")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if bad, err := v.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("VerifyAuditChain after a lock cycle: bad=%d err=%v", bad, err)
	}
}

// Recovery re-wraps the same DEK under a new password, so the subkey is unchanged and
// pre-recovery records must still verify.
func TestAuditKeySurvivesRecovery(t *testing.T) {
	v := newInitedVault(t)
	if _, err := v.AddSecret(AddSecretInput{
		Alias: "K1", ProviderKey: "github", Environment: Dev, Value: []byte("v"),
	}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	code, err := v.GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey: %v", err)
	}

	v.Lock()
	if err := v.RecoverWithKey(code, []byte("new-password")); err != nil {
		t.Fatalf("RecoverWithKey: %v", err)
	}

	if bad, err := v.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("VerifyAuditChain after recovery: bad=%d err=%v", bad, err)
	}
	// The "recover" record itself must be authenticated, not chain-only.
	var mac []byte
	if err := v.DB().SQL().QueryRow(
		`SELECT mac FROM audit_log WHERE action='recover' AND outcome='allow' ORDER BY seq DESC LIMIT 1`,
	).Scan(&mac); err != nil {
		t.Fatalf("read recover record: %v", err)
	}
	if len(mac) == 0 {
		t.Fatal("the recover record is unauthenticated")
	}
}

// The auto-lock record is written by the same call that destroys the key, so ordering
// decides whether it can be authenticated.
func TestAutoLockRecordIsKeyed(t *testing.T) {
	v := newInitedVault(t)
	if !v.AutoLockIfIdle(0) {
		t.Fatal("AutoLockIfIdle(0) did not lock an unlocked vault")
	}
	if v.Unlocked() {
		t.Fatal("vault still unlocked after auto-lock")
	}

	var mac []byte
	if err := v.DB().SQL().QueryRow(
		`SELECT mac FROM audit_log WHERE action='autolock' ORDER BY seq DESC LIMIT 1`,
	).Scan(&mac); err != nil {
		t.Fatalf("read autolock record: %v", err)
	}
	if len(mac) == 0 {
		t.Fatal("the autolock record is unauthenticated — it must be logged before the key is zeroized")
	}
}

// End-to-end version of the attack the keyed layer exists to stop, driven through the
// vault rather than the audit package.
func TestVaultDetectsRewrittenAuditLog(t *testing.T) {
	v := newInitedVault(t)
	if _, err := v.AddSecret(AddSecretInput{
		Alias: "AWS_PROD", ProviderKey: "aws", Environment: Prod, Value: []byte("v"),
	}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	if _, err := v.Reveal("AWS_PROD"); err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if bad, err := v.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("baseline VerifyAuditChain: bad=%d err=%v", bad, err)
	}

	// Erase the evidence of the reveal and repair the chain the way an attacker with
	// database access would.
	sq := v.DB().SQL()
	if _, err := sq.Exec(`DELETE FROM audit_log WHERE action='reveal'`); err != nil {
		t.Fatalf("delete reveal record: %v", err)
	}
	rows, err := sq.Query(`SELECT seq,ts,actor,action,target,outcome,detail FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	type rec struct {
		seq                                    int64
		ts                                     int64
		actor, action, target, outcome, detail string
	}
	var recs []rec
	for rows.Next() {
		var r rec
		if err := rows.Scan(&r.seq, &r.ts, &r.actor, &r.action, &r.target, &r.outcome, &r.detail); err != nil {
			rows.Close()
			t.Fatalf("scan: %v", err)
		}
		recs = append(recs, r)
	}
	rows.Close()

	prev := make([]byte, 32)
	for _, r := range recs {
		var h []byte
		// Recompute the chain hash exactly as the audit package would.
		h = auditChainHashForTest(prev, r.ts, r.actor, r.action, r.target, audit.Outcome(r.outcome), r.detail)
		if _, err := sq.Exec(`UPDATE audit_log SET prev_hash=?, hash=? WHERE seq=?`, prev, h, r.seq); err != nil {
			t.Fatalf("rewrite: %v", err)
		}
		prev = h
	}

	bad, err := v.VerifyAuditChain()
	if err == nil && bad == 0 {
		t.Fatal("vault accepted an audit log with a reveal record surgically removed")
	}
}
