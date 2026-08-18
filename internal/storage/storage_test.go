package storage

import "testing"

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

	// vault_meta table must exist (query should not error).
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
	var v int
	if err := db.SQL().QueryRow(`SELECT max(version) FROM schema_migrations`).Scan(&v); err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	if v < 1 {
		t.Fatalf("expected migration version >=1, got %d", v)
	}
}
