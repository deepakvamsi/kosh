package storage

import (
	"fmt"
	"testing"
)

func TestOpenRunsMigrationsAndSeeds(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	defer db.Close()

	var n int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM providers WHERE is_builtin=1`).Scan(&n); err != nil {
		t.Fatalf("count providers: %v", err)
	}
	if n < 20 {
		t.Fatalf("expected >=20 seeded providers, got %d", n)
	}

	var meta int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM vault_meta`).Scan(&meta); err != nil {
		t.Fatalf("vault_meta not created: %v", err)
	}
}

func TestSeedIdempotent(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.seedProviders(); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	var n int
	db.SQL().QueryRow(`SELECT count(*) FROM providers WHERE key='openai'`).Scan(&n)
	if n != 1 {
		t.Fatalf("openai provider should be unique, got %d", n)
	}
}

func TestMigrationsRecorded(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	v, err := SchemaVersion(db.SQL())
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v < 5 {
		t.Fatalf("expected schema version >=5 (all migrations applied), got %d", v)
	}
}

func TestAllColumnsExist(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	cols := []struct {
		table  string
		column string
	}{
		{"secrets", "custom_fields"},
		{"secrets", "item_type"},
		{"secrets", "is_favorite"},
		{"secrets", "totp_enc"},
	}
	for _, c := range cols {
		q := fmt.Sprintf(`SELECT %s FROM %s LIMIT 0`, c.column, c.table)
		if _, err := db.SQL().Exec(q); err != nil {
			t.Errorf("column %s.%s missing: %v", c.table, c.column, err)
		}
	}

	var hist int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM secret_history`).Scan(&hist); err != nil {
		t.Errorf("secret_history table missing: %v", err)
	}
}

func TestMigrationIdempotent(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := migrate(db.SQL()); err != nil {
		t.Fatalf("second migrate() call failed: %v", err)
	}

	if err := migrate(db.SQL()); err != nil {
		t.Fatalf("third migrate() call failed: %v", err)
	}

	v, _ := SchemaVersion(db.SQL())
	if v < 5 {
		t.Fatalf("schema version should still be >=5 after re-runs, got %d", v)
	}
}
