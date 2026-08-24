package backup

import (
	"testing"

	"kosh/internal/vault"
)

// A restore installs the archive's key material, which changes the DEK and therefore the
// audit MAC subkey. Every pre-restore record MAC becomes unverifiable. The restore must
// downgrade those records to chain-only and clear the head anchor, or the next unlock
// reports the entire log as tampered — a false alarm on a routine operation.
func TestRestoreLeavesAuditLogVerifiable(t *testing.T) {
	// Source vault: the archive we will restore.
	srcDB, srcV := newVault(t)
	if _, err := srcV.AddSecret(vault.AddSecretInput{
		Alias: "SRC", ProviderKey: "openai", Environment: vault.Dev, Value: []byte("src-value"),
	}); err != nil {
		t.Fatalf("AddSecret(src): %v", err)
	}
	archive, err := Export(srcDB.SQL(), []byte("pw"))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// Target vault: a different vault, with its own DEK and its own keyed audit records.
	dstDB, dstV := newVault(t)
	if _, err := dstV.AddSecret(vault.AddSecretInput{
		Alias: "DST", ProviderKey: "aws", Environment: vault.Prod, Value: []byte("dst-value"),
	}); err != nil {
		t.Fatalf("AddSecret(dst): %v", err)
	}
	if bad, err := dstV.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("baseline VerifyAuditChain: bad=%d err=%v", bad, err)
	}

	var keyedBefore int
	if err := dstDB.SQL().QueryRow(`SELECT count(*) FROM audit_log WHERE mac IS NOT NULL`).Scan(&keyedBefore); err != nil {
		t.Fatalf("count: %v", err)
	}
	if keyedBefore == 0 {
		t.Fatal("expected the target vault to have authenticated audit records before the restore")
	}

	if err := Import(dstDB.SQL(), archive, []byte("pw")); err != nil {
		t.Fatalf("Import: %v", err)
	}
	// The app locks after a restore; the user re-unlocks with the archive's password.
	dstV.Lock()
	if err := dstV.Unlock([]byte("pw")); err != nil {
		t.Fatalf("Unlock after restore: %v", err)
	}

	// The whole point: no false tamper report.
	if bad, err := dstV.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("VerifyAuditChain after restore: bad=%d err=%v", bad, err)
	}

	// History is preserved, not deleted.
	var total int
	if err := dstDB.SQL().QueryRow(`SELECT count(*) FROM audit_log`).Scan(&total); err != nil {
		t.Fatalf("count: %v", err)
	}
	if total < keyedBefore {
		t.Fatalf("audit records dropped from %d to %d during restore", keyedBefore, total)
	}

	// The restore itself is recorded.
	var n int
	if err := dstDB.SQL().QueryRow(
		`SELECT count(*) FROM audit_log WHERE action='import_backup'`).Scan(&n); err != nil {
		t.Fatalf("count import_backup: %v", err)
	}
	if n != 1 {
		t.Fatalf("import_backup audit records = %d, want 1", n)
	}

	// Post-restore activity is authenticated again under the new key.
	if _, err := dstV.AddSecret(vault.AddSecretInput{
		Alias: "AFTER", ProviderKey: "github", Environment: vault.Dev, Value: []byte("after"),
	}); err != nil {
		t.Fatalf("AddSecret after restore: %v", err)
	}
	var keyedAfter int
	if err := dstDB.SQL().QueryRow(`SELECT count(*) FROM audit_log WHERE mac IS NOT NULL`).Scan(&keyedAfter); err != nil {
		t.Fatalf("count: %v", err)
	}
	if keyedAfter == 0 {
		t.Fatal("no authenticated records after the restore — the chain never re-anchored")
	}
	if bad, err := dstV.VerifyAuditChain(); err != nil || bad != 0 {
		t.Fatalf("VerifyAuditChain after post-restore write: bad=%d err=%v", bad, err)
	}
}
