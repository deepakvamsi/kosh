package storage

import (
	"database/sql"
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
	if v < 7 {
		t.Fatalf("expected schema version >=7 (all migrations applied), got %d", v)
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

	// secret_history was removed in migration 0006 — the table must not exist.
	var name string
	err = db.SQL().QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='secret_history'`).Scan(&name)
	if err != sql.ErrNoRows {
		t.Errorf("secret_history table should be dropped by 0006; got name=%q err=%v", name, err)
	}
}

// TestMigration0007PreservesData builds a database through migration 0006, inserts a
// secret with a tag association, then applies 0007 (the secrets-table rebuild that
// widens the item_type CHECK to include 'keypair'). It asserts the secret's ciphertext
// and its tag link survive the rebuild, and that a 'keypair' row is now insertable while
// a bogus item_type is still rejected. This guards the highest-risk migration against
// the data-loss class of bug that a table rebuild can introduce.
func TestMigration0007PreservesData(t *testing.T) {
	dir := t.TempDir()
	dsn := fmt.Sprintf("file:%s/t.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", dir)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	migs, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}

	// Apply everything up to and including 0006.
	for _, m := range migs {
		if m.version <= 6 {
			if err := applyMigration(db, m); err != nil {
				t.Fatalf("apply migration %d: %v", m.version, err)
			}
		}
	}

	// Seed a provider, a secret (with distinctive ciphertext), a tag, and the link.
	if _, err := db.Exec(`INSERT INTO providers(key,name,category,is_builtin,created_at) VALUES('aws','AWS','cloud',1,1)`); err != nil {
		t.Fatal(err)
	}
	var pid int64
	if err := db.QueryRow(`SELECT id FROM providers WHERE key='aws'`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	cipher := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if _, err := db.Exec(
		`INSERT INTO secrets(alias,provider_id,environment,value_enc,value_hash,created_at,updated_at,item_type)
		 VALUES('KEEP_ME',?, 'prod', ?, ?, 1, 1, 'api_key')`, pid, cipher, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	var sid int64
	if err := db.QueryRow(`SELECT id FROM secrets WHERE alias='KEEP_ME'`).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tags(name) VALUES('prod-tag')`); err != nil {
		t.Fatal(err)
	}
	var tid int64
	if err := db.QueryRow(`SELECT id FROM tags WHERE name='prod-tag'`).Scan(&tid); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO secret_tags(secret_id,tag_id) VALUES(?,?)`, sid, tid); err != nil {
		t.Fatal(err)
	}

	// Apply 0007 — the rebuild.
	var applied bool
	for _, m := range migs {
		if m.version == 7 {
			if err := applyMigration(db, m); err != nil {
				t.Fatalf("apply migration 7: %v", err)
			}
			applied = true
		}
	}
	if !applied {
		t.Fatal("migration 0007 not found")
	}

	// The secret survived with its ciphertext intact.
	var gotCipher []byte
	var gotType string
	if err := db.QueryRow(`SELECT value_enc, item_type FROM secrets WHERE alias='KEEP_ME'`).Scan(&gotCipher, &gotType); err != nil {
		t.Fatalf("secret lost after rebuild: %v", err)
	}
	if string(gotCipher) != string(cipher) || gotType != "api_key" {
		t.Fatalf("secret corrupted: cipher=%x type=%q", gotCipher, gotType)
	}

	// The tag association survived (same ids).
	var links int
	if err := db.QueryRow(`SELECT count(*) FROM secret_tags WHERE secret_id=? AND tag_id=?`, sid, tid).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if links != 1 {
		t.Fatalf("tag association lost after rebuild: got %d", links)
	}

	// 'keypair' is now a valid item_type; a bogus type is still rejected by the CHECK.
	if _, err := db.Exec(
		`INSERT INTO secrets(alias,provider_id,environment,value_enc,value_hash,created_at,updated_at,item_type)
		 VALUES('KP',?, 'dev', ?, ?, 1, 1, 'keypair')`, pid, cipher, []byte{0x02}); err != nil {
		t.Fatalf("keypair item_type rejected after 0007: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO secrets(alias,provider_id,environment,value_enc,value_hash,created_at,updated_at,item_type)
		 VALUES('BAD',?, 'dev', ?, ?, 1, 1, 'bogus')`, pid, cipher, []byte{0x03}); err == nil {
		t.Fatal("expected CHECK to reject bogus item_type after 0007")
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
	if v < 7 {
		t.Fatalf("schema version should still be >=7 after re-runs, got %d", v)
	}
}
