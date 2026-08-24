package audit

import (
	"database/sql"
	"testing"

	"kosh/internal/storage"
)

var (
	testKey  = []byte("0123456789abcdef0123456789abcdef")
	otherKey = []byte("fedcba9876543210fedcba9876543210")
)

// newKeyedDB returns an in-memory database with the vault_meta row that keyed appends
// need for the head anchor. In production Init writes that row in the same transaction
// as the first audit record.
func newKeyedDB(t *testing.T) *storage.DB {
	t.Helper()
	db := newDB(t)
	if _, err := db.SQL().Exec(
		`INSERT INTO vault_meta(id,kdf,kdf_time,kdf_memory_kib,kdf_threads,kdf_salt,verifier,dek_wrapped,schema_version,created_at,updated_at)
		 VALUES(1,'argon2id',3,65536,4,X'00',X'00',X'00',1,0,0)`,
	); err != nil {
		t.Fatalf("seed vault_meta: %v", err)
	}
	return db
}

func mustLogKeyed(t *testing.T, db *storage.DB, action, target string, outcome Outcome) {
	t.Helper()
	if err := LogKeyed(db.SQL(), testKey, "ui", action, target, outcome, ""); err != nil {
		t.Fatalf("LogKeyed(%s): %v", action, err)
	}
}

func mustVerifyClean(t *testing.T, db *storage.DB) {
	t.Helper()
	bad, err := VerifyChainKeyed(db.SQL(), testKey)
	if err != nil {
		t.Fatalf("VerifyChainKeyed: %v", err)
	}
	if bad != 0 {
		t.Fatalf("expected an intact log, got a break at seq %d", bad)
	}
}

// rewriteChainFrom simulates the attacker this whole layer exists for: someone with
// write access to vault.db who edits the log and then recomputes every downstream
// hash so the plain chain still lines up. Optionally strips MACs as it goes.
func rewriteChainFrom(t *testing.T, db *storage.DB, stripMACs bool) {
	t.Helper()
	sq := db.SQL()
	rows, err := sq.Query(`SELECT seq,ts,actor,action,target,outcome,detail FROM audit_log ORDER BY seq ASC`)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	type rec struct {
		seq                            int64
		ts                             int64
		actor, action, target, outcome string
		detail                         string
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

	prev := genesis
	for _, r := range recs {
		h := chainHash(prev, r.ts, r.actor, r.action, r.target, Outcome(r.outcome), r.detail)
		if stripMACs {
			if _, err := sq.Exec(`UPDATE audit_log SET prev_hash=?, hash=?, mac=NULL WHERE seq=?`, prev, h, r.seq); err != nil {
				t.Fatalf("rewrite seq %d: %v", r.seq, err)
			}
		} else {
			if _, err := sq.Exec(`UPDATE audit_log SET prev_hash=?, hash=? WHERE seq=?`, prev, h, r.seq); err != nil {
				t.Fatalf("rewrite seq %d: %v", r.seq, err)
			}
		}
		prev = h
	}
}

func TestKeyedLogVerifies(t *testing.T) {
	db := newKeyedDB(t)
	mustLogKeyed(t, db, "init", "", Allow)
	mustLogKeyed(t, db, "create", "OPENAI_DEV", Allow)
	mustLogKeyed(t, db, "reveal", "OPENAI_DEV", Allow)
	mustVerifyClean(t, db)

	// The plain chain must still verify too — the keyed layer is additive.
	if bad, err := VerifyChain(db.SQL()); err != nil || bad != 0 {
		t.Fatalf("VerifyChain: bad=%d err=%v", bad, err)
	}
}

// The core regression: an attacker who edits a record and recomputes the whole chain
// defeats VerifyChain but not VerifyChainKeyed. If this test ever fails, the
// "tamper-evident" claim is back to meaning "detects accidental corruption".
func TestFullChainRewriteIsDetected(t *testing.T) {
	db := newKeyedDB(t)
	mustLogKeyed(t, db, "init", "", Allow)
	mustLogKeyed(t, db, "reveal", "AWS_PROD", Allow)
	mustLogKeyed(t, db, "delete", "AWS_PROD", Allow)

	// Doctor the middle record, then repair every hash after it.
	if _, err := db.SQL().Exec(`UPDATE audit_log SET action='noop', target='' WHERE seq=2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	rewriteChainFrom(t, db, false)

	// The unkeyed walk is fooled — this is precisely the weakness being fixed, and
	// asserting it keeps the test honest about what each layer buys.
	if bad, err := VerifyChain(db.SQL()); err != nil || bad != 0 {
		t.Fatalf("expected the plain chain to be fooled by a full rewrite: bad=%d err=%v", bad, err)
	}

	bad, err := VerifyChainKeyed(db.SQL(), testKey)
	if err != nil {
		t.Fatalf("VerifyChainKeyed: %v", err)
	}
	if bad == 0 {
		t.Fatal("keyed verification accepted a rewritten chain")
	}
}

func TestDeletedRecordIsDetected(t *testing.T) {
	db := newKeyedDB(t)
	mustLogKeyed(t, db, "init", "", Allow)
	mustLogKeyed(t, db, "reveal", "AWS_PROD", Allow) // the record to hide
	mustLogKeyed(t, db, "update", "AWS_PROD", Allow)

	if _, err := db.SQL().Exec(`DELETE FROM audit_log WHERE seq=2`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rewriteChainFrom(t, db, false)

	bad, err := VerifyChainKeyed(db.SQL(), testKey)
	if err != nil {
		t.Fatalf("VerifyChainKeyed: %v", err)
	}
	if bad == 0 {
		t.Fatal("keyed verification accepted a log with a record removed from the middle")
	}
}

// Truncation is the edit a per-record MAC cannot see: the removed records took their
// MACs with them. The head anchor is what catches it.
func TestTailTruncationIsDetected(t *testing.T) {
	db := newKeyedDB(t)
	mustLogKeyed(t, db, "init", "", Allow)
	mustLogKeyed(t, db, "reveal", "AWS_PROD", Allow)
	mustLogKeyed(t, db, "export_backup", "", Allow) // the record to hide

	if _, err := db.SQL().Exec(`DELETE FROM audit_log WHERE seq=3`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	// Everything that remains is internally consistent, so the chain walk is clean.
	if bad, err := VerifyChain(db.SQL()); err != nil || bad != 0 {
		t.Fatalf("expected the plain chain to miss a truncation: bad=%d err=%v", bad, err)
	}

	bad, err := VerifyChainKeyed(db.SQL(), testKey)
	if err != nil {
		t.Fatalf("VerifyChainKeyed: %v", err)
	}
	if bad == 0 {
		t.Fatal("keyed verification accepted a truncated log")
	}
}

// Stripping MACs to dodge the per-record check does not work either: the anchor still
// names a record whose MAC is gone.
func TestMACStrippingIsDetected(t *testing.T) {
	db := newKeyedDB(t)
	mustLogKeyed(t, db, "init", "", Allow)
	mustLogKeyed(t, db, "reveal", "AWS_PROD", Allow)
	mustLogKeyed(t, db, "delete", "AWS_PROD", Allow)

	if _, err := db.SQL().Exec(`UPDATE audit_log SET action='noop' WHERE seq=2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	rewriteChainFrom(t, db, true) // rewrite hashes AND clear every mac

	bad, err := VerifyChainKeyed(db.SQL(), testKey)
	if bad == 0 && err == nil {
		t.Fatal("keyed verification accepted a log with every MAC stripped")
	}
}

// Forging the anchor requires the key.
func TestForgedAnchorIsDetected(t *testing.T) {
	db := newKeyedDB(t)
	mustLogKeyed(t, db, "init", "", Allow)
	mustLogKeyed(t, db, "reveal", "AWS_PROD", Allow)

	if _, err := db.SQL().Exec(`UPDATE vault_meta SET audit_head_mac=X'DEADBEEF' WHERE id=1`); err != nil {
		t.Fatalf("forge anchor: %v", err)
	}
	bad, err := VerifyChainKeyed(db.SQL(), testKey)
	if err != nil {
		t.Fatalf("VerifyChainKeyed: %v", err)
	}
	if bad == 0 {
		t.Fatal("keyed verification accepted a forged head anchor")
	}
}

func TestClearedAnchorIsDetected(t *testing.T) {
	db := newKeyedDB(t)
	mustLogKeyed(t, db, "init", "", Allow)

	if _, err := db.SQL().Exec(`UPDATE vault_meta SET audit_head_seq=NULL, audit_head_mac=NULL WHERE id=1`); err != nil {
		t.Fatalf("clear anchor: %v", err)
	}
	if _, err := VerifyChainKeyed(db.SQL(), testKey); err == nil {
		t.Fatal("want an error when keyed records exist but the anchor is gone")
	}
}

// Verifying with the wrong key must fail closed, not pass.
func TestWrongKeyFails(t *testing.T) {
	db := newKeyedDB(t)
	mustLogKeyed(t, db, "init", "", Allow)
	mustLogKeyed(t, db, "reveal", "X", Allow)

	bad, err := VerifyChainKeyed(db.SQL(), otherKey)
	if err != nil {
		t.Fatalf("VerifyChainKeyed: %v", err)
	}
	if bad == 0 {
		t.Fatal("keyed verification passed under the wrong key")
	}
}

func TestVerifyChainKeyedRequiresAKey(t *testing.T) {
	db := newKeyedDB(t)
	mustLogKeyed(t, db, "init", "", Allow)
	if _, err := VerifyChainKeyed(db.SQL(), nil); err == nil {
		t.Fatal("want an error when called without a key")
	}
}

// Locked-vault events cannot be keyed. They must interleave with keyed records without
// breaking verification — otherwise a failed unlock would look like tampering.
func TestUnkeyedRecordsInterleaveCleanly(t *testing.T) {
	db := newKeyedDB(t)
	sq := db.SQL()

	mustLogKeyed(t, db, "init", "", Allow)
	if err := Log(sq, "ui", "unlock", "", Deny, "wrong password"); err != nil { // locked: no key
		t.Fatalf("Log: %v", err)
	}
	mustLogKeyed(t, db, "unlock", "", Allow)
	if err := Log(sq, "ui", "autolock", "", Allow, ""); err != nil {
		t.Fatalf("Log: %v", err)
	}

	mustVerifyClean(t, db)

	// Sanity: exactly the locked-state records lack a MAC.
	var unkeyed int
	if err := sq.QueryRow(`SELECT count(*) FROM audit_log WHERE mac IS NULL`).Scan(&unkeyed); err != nil {
		t.Fatalf("count: %v", err)
	}
	if unkeyed != 2 {
		t.Fatalf("unkeyed record count = %d, want 2", unkeyed)
	}
}

// A pre-0008 vault has no MACs at all. Keyed verification must not treat that as
// tampering, or every upgraded install would report a broken log on first launch.
func TestLegacyLogWithNoMACsVerifies(t *testing.T) {
	db := newKeyedDB(t)
	sq := db.SQL()
	for _, a := range []string{"init", "unlock", "create"} {
		if err := Log(sq, "ui", a, "", Allow, ""); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	mustVerifyClean(t, db)
}

// The anchor must be written in the same transaction as the record, so a rolled-back
// append leaves neither behind.
func TestRolledBackKeyedAppendLeavesNoTrace(t *testing.T) {
	db := newKeyedDB(t)
	sq := db.SQL()
	mustLogKeyed(t, db, "init", "", Allow)

	var seqBefore sql.NullInt64
	if err := sq.QueryRow(`SELECT audit_head_seq FROM vault_meta WHERE id=1`).Scan(&seqBefore); err != nil {
		t.Fatalf("read anchor: %v", err)
	}

	tx, err := sq.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := LogTxKeyed(tx, testKey, "ui", "reveal", "SECRET", Allow, ""); err != nil {
		t.Fatalf("LogTxKeyed: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	var seqAfter sql.NullInt64
	if err := sq.QueryRow(`SELECT audit_head_seq FROM vault_meta WHERE id=1`).Scan(&seqAfter); err != nil {
		t.Fatalf("read anchor: %v", err)
	}
	if seqBefore != seqAfter {
		t.Fatalf("anchor moved on a rolled-back append: %v -> %v", seqBefore, seqAfter)
	}
	mustVerifyClean(t, db)
}

// A keyed append with no vault_meta row cannot store its anchor, and must fail loudly
// rather than write a record that only looks protected.
func TestKeyedAppendWithoutVaultMetaFails(t *testing.T) {
	db := newDB(t) // deliberately no vault_meta row
	if err := LogKeyed(db.SQL(), testKey, "ui", "init", "", Allow, ""); err == nil {
		t.Fatal("want an error when the head anchor cannot be stored")
	}
}
