package audit

import (
	"testing"

	"kosh/internal/storage"
)

func newDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.OpenMemory()
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLogAndVerifyChain(t *testing.T) {
	db := newDB(t)
	sq := db.SQL()

	if err := Log(sq, "ui", "unlock", "", Allow, ""); err != nil {
		t.Fatal(err)
	}
	if err := Log(sq, "cli:keyvault", "reveal", "OPENAI_DEV", Allow, ""); err != nil {
		t.Fatal(err)
	}
	if err := Log(sq, "agent:cursor", "reveal", "AWS_PROD", Deny, "prod not permitted"); err != nil {
		t.Fatal(err)
	}

	bad, err := VerifyChain(sq)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if bad != 0 {
		t.Fatalf("expected intact chain, got break at seq %d", bad)
	}
}

func TestTamperBreaksChain(t *testing.T) {
	db := newDB(t)
	sq := db.SQL()

	Log(sq, "ui", "unlock", "", Allow, "")
	Log(sq, "ui", "reveal", "OPENAI_DEV", Allow, "")

	// Tamper: change an existing record's target after the fact.
	if _, err := sq.Exec(`UPDATE audit_log SET target='GITHUB_DEV' WHERE seq=2`); err != nil {
		t.Fatal(err)
	}

	bad, err := VerifyChain(sq)
	if err != nil {
		t.Fatal(err)
	}
	if bad != 2 {
		t.Fatalf("expected chain break at seq 2, got %d", bad)
	}
}

func TestDeleteBreaksChain(t *testing.T) {
	db := newDB(t)
	sq := db.SQL()

	Log(sq, "ui", "a", "", Allow, "")
	Log(sq, "ui", "b", "", Allow, "")
	Log(sq, "ui", "c", "", Allow, "")

	// Delete the middle record; the following record's prev_hash no longer matches.
	if _, err := sq.Exec(`DELETE FROM audit_log WHERE seq=2`); err != nil {
		t.Fatal(err)
	}
	bad, err := VerifyChain(sq)
	if err != nil {
		t.Fatal(err)
	}
	if bad != 3 {
		t.Fatalf("expected chain break at seq 3, got %d", bad)
	}
}

func TestListNewestFirst(t *testing.T) {
	db := newDB(t)
	sq := db.SQL()
	Log(sq, "ui", "first", "", Allow, "")
	Log(sq, "ui", "second", "", Allow, "")

	recs, err := List(sq, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
	if recs[0].Action != "second" {
		t.Fatalf("expected newest first, got %q", recs[0].Action)
	}
}
