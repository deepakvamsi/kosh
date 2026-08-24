package storage

import (
	"strings"
	"testing"
)

// --- splitStatements ---------------------------------------------------------------

func TestSplitStatementsBasics(t *testing.T) {
	got := splitStatements("CREATE TABLE a(x INT);\nCREATE TABLE b(y INT);\n")
	if len(got) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(got), got)
	}
}

func TestSplitStatementsStripsComments(t *testing.T) {
	script := `
-- a leading line comment
CREATE TABLE a(x INT); -- trailing comment
/* a block
   comment spanning lines */
CREATE TABLE b(y INT);
`
	got := splitStatements(script)
	if len(got) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(got), got)
	}
	for _, s := range got {
		if strings.Contains(s, "comment") {
			t.Errorf("comment text survived into a statement: %q", s)
		}
	}
}

// The old line-based splitter cut on ANY line containing a semicolon, so a semicolon
// inside a string literal produced two fragments that were each executed.
func TestSplitStatementsIgnoresSemicolonInStringLiteral(t *testing.T) {
	script := `INSERT INTO t(v) VALUES('a;b');
INSERT INTO t(v) VALUES('c');`
	got := splitStatements(script)
	if len(got) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(got), got)
	}
	if !strings.Contains(got[0], "'a;b'") {
		t.Errorf("string literal was split: %q", got[0])
	}
}

func TestSplitStatementsHandlesEscapedQuote(t *testing.T) {
	script := `INSERT INTO t(v) VALUES('it''s; fine');
SELECT 1;`
	got := splitStatements(script)
	if len(got) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(got), got)
	}
	if !strings.Contains(got[0], `'it''s; fine'`) {
		t.Errorf("escaped quote mishandled: %q", got[0])
	}
}

// A trigger body contains semicolons that are not statement terminators.
func TestSplitStatementsKeepsTriggerBodyIntact(t *testing.T) {
	script := `CREATE TRIGGER t_ai AFTER INSERT ON t
BEGIN
  UPDATE t SET n = n + 1 WHERE id = new.id;
  DELETE FROM u WHERE id = new.id;
END;
SELECT 1;`
	got := splitStatements(script)
	if len(got) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(got), got)
	}
	if !strings.Contains(got[0], "DELETE FROM u") || !strings.Contains(got[0], "END") {
		t.Errorf("trigger body was split: %q", got[0])
	}
}

func TestSplitStatementsIgnoresSemicolonInQuotedIdentifier(t *testing.T) {
	got := splitStatements(`CREATE TABLE "weird;name"(x INT);
SELECT 1;`)
	if len(got) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(got), got)
	}
}

func TestSplitStatementsHandlesMissingTrailingSemicolon(t *testing.T) {
	got := splitStatements("SELECT 1;\nSELECT 2")
	if len(got) != 2 {
		t.Fatalf("got %d statements, want 2: %q", len(got), got)
	}
}

func TestSplitStatementsIgnoresCommentOnlyScript(t *testing.T) {
	if got := splitStatements("-- nothing here\n/* or here */\n"); len(got) != 0 {
		t.Fatalf("got %d statements, want 0: %q", len(got), got)
	}
}

// --- ALTER TABLE … ADD COLUMN parsing --------------------------------------------

func TestAddColumnParsing(t *testing.T) {
	cases := []struct {
		stmt        string
		wantTable   string
		wantColumn  string
		shouldMatch bool
	}{
		{stmt: `ALTER TABLE secrets ADD COLUMN item_type TEXT NOT NULL DEFAULT 'api_key'`, wantTable: "secrets", wantColumn: "item_type", shouldMatch: true},
		{stmt: "ALTER TABLE audit_log ADD COLUMN mac BLOB", wantTable: "audit_log", wantColumn: "mac", shouldMatch: true},
		{stmt: "alter table  vault_meta   add  audit_head_seq INTEGER", wantTable: "vault_meta", wantColumn: "audit_head_seq", shouldMatch: true},
		{stmt: `ALTER TABLE "odd name" ADD COLUMN "odd col" TEXT`, wantTable: "odd name", wantColumn: "odd col", shouldMatch: true},
		{stmt: "ALTER TABLE secrets RENAME TO secrets_old", shouldMatch: false},
		{stmt: "CREATE TABLE t(x INT)", shouldMatch: false},
		{stmt: "DROP TABLE secrets", shouldMatch: false},
	}
	for _, tc := range cases {
		m := addColumnRE.FindStringSubmatch(tc.stmt)
		if tc.shouldMatch != (m != nil) {
			t.Errorf("match(%q) = %v, want %v", tc.stmt, m != nil, tc.shouldMatch)
			continue
		}
		if m == nil {
			continue
		}
		if got := unquoteIdent(m[1]); got != tc.wantTable {
			t.Errorf("table for %q = %q, want %q", tc.stmt, got, tc.wantTable)
		}
		if got := unquoteIdent(m[2]); got != tc.wantColumn {
			t.Errorf("column for %q = %q, want %q", tc.stmt, got, tc.wantColumn)
		}
	}
}

// --- applyMigration idempotency and failure behaviour ----------------------------

func TestApplyMigrationSkipsExistingColumnByIntrospection(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	defer db.Close()
	sq := db.SQL()

	if _, err := sq.Exec(`CREATE TABLE t(a INT, b INT)`); err != nil {
		t.Fatalf("create: %v", err)
	}

	// `b` already exists; `c` does not. The migration must skip one and apply the other.
	m := migration{version: 9001, name: "9001_test.sql", sql: `
ALTER TABLE t ADD COLUMN b INT;
ALTER TABLE t ADD COLUMN c INT;
`}
	if err := applyMigration(sq, m); err != nil {
		t.Fatalf("applyMigration: %v", err)
	}

	var n int
	if err := sq.QueryRow(`SELECT count(*) FROM pragma_table_info('t') WHERE name='c'`).Scan(&n); err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if n != 1 {
		t.Fatal("column c was not added")
	}
	if err := sq.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=9001`).Scan(&n); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if n != 1 {
		t.Fatal("migration was not recorded")
	}

	// Re-run the same migration against the now-upgraded schema. This is the exact
	// scenario idempotency exists for: an older binary applied the ALTERs but the
	// version was never recorded, so migrate() will try again. (migrate() itself skips
	// versions already in schema_migrations, so drop the row to reach this path.)
	if _, err := sq.Exec(`DELETE FROM schema_migrations WHERE version=9001`); err != nil {
		t.Fatalf("clear recorded version: %v", err)
	}
	if err := applyMigration(sq, m); err != nil {
		t.Fatalf("re-apply against an already-upgraded schema: %v", err)
	}
}

// The old runner swallowed any error whose text happened to contain "already exists" and
// then recorded the migration as applied. A real failure must now roll back and NOT be
// recorded, or the database silently diverges from the schema it claims.
func TestApplyMigrationFailsLoudlyAndRollsBack(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	defer db.Close()
	sq := db.SQL()

	m := migration{version: 9002, name: "9002_test.sql", sql: `
CREATE TABLE good(x INT);
THIS IS NOT SQL;
`}
	if err := applyMigration(sq, m); err == nil {
		t.Fatal("applyMigration accepted a broken statement")
	}

	var n int
	if err := sq.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version=9002`).Scan(&n); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if n != 0 {
		t.Fatal("a failed migration was recorded as applied")
	}
	// The earlier statement in the same migration must have rolled back too.
	if err := sq.QueryRow(
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='good'`).Scan(&n); err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	if n != 0 {
		t.Fatal("a failed migration left a partially applied schema behind")
	}
}

// A duplicate-column error that is NOT an ADD COLUMN we can introspect must still fail,
// rather than being pattern-matched into silence.
func TestApplyMigrationDoesNotSwallowDuplicateTable(t *testing.T) {
	db, err := OpenMemory()
	if err != nil {
		t.Fatalf("OpenMemory: %v", err)
	}
	defer db.Close()
	sq := db.SQL()

	if _, err := sq.Exec(`CREATE TABLE dup(x INT)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	m := migration{version: 9003, name: "9003_test.sql", sql: `CREATE TABLE dup(x INT);`}
	if err := applyMigration(sq, m); err == nil {
		t.Fatal("a duplicate CREATE TABLE was silently accepted")
	}
}

// --- loadMigrations --------------------------------------------------------------

func TestLoadMigrationsAreOrderedAndUnique(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("no migrations loaded")
	}
	for i := 1; i < len(migs); i++ {
		if migs[i].version <= migs[i-1].version {
			t.Fatalf("migrations out of order or duplicated: %s then %s", migs[i-1].name, migs[i].name)
		}
	}
}

// Every ALTER TABLE … ADD COLUMN in the real migration set must be parseable, otherwise
// it loses its idempotent upgrade path and would fail on a partially upgraded database.
func TestRealMigrationsAddColumnStatementsAreParseable(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, m := range migs {
		for _, stmt := range splitStatements(m.sql) {
			up := strings.ToUpper(stmt)
			if !strings.Contains(up, "ALTER TABLE") || !strings.Contains(up, "ADD ") {
				continue
			}
			if strings.Contains(up, "RENAME") {
				continue
			}
			if addColumnRE.FindStringSubmatch(stmt) == nil {
				t.Errorf("%s: ADD COLUMN statement not parseable, so it has no idempotent path: %q",
					m.name, truncate(stmt, 80))
			}
		}
	}
}
