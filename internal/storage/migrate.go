package storage

import (
	"database/sql"
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("storage: read migrations dir: %w", err)
	}
	var out []migration
	seen := map[int]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(e.Name(), "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("storage: bad migration filename %q", e.Name())
		}
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("storage: bad migration version %q: %w", e.Name(), err)
		}
		// Two files claiming the same version would apply in an order that depends on
		// directory listing, and only one would be recorded. Refuse rather than pick.
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("storage: duplicate migration version %d (%s and %s)", v, prev, e.Name())
		}
		seen[v] = e.Name()
		b, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// splitStatements splits a SQL script into individual statements.
//
// It is a character scanner, not a line splitter, because a semicolon is only a
// statement terminator when it appears outside a string literal, outside a comment, and
// outside a BEGIN … END block. A trigger body or a value containing ';' would otherwise
// be chopped in half and produce a syntax error — or worse, two statements that each
// parse but do the wrong thing.
func splitStatements(script string) []string {
	var (
		stmts []string
		cur   strings.Builder
		// depth of BEGIN … END nesting; semicolons inside a block do not terminate.
		blockDepth int
	)

	flush := func() {
		s := strings.TrimSpace(cur.String())
		cur.Reset()
		if s == "" || s == ";" {
			return
		}
		stmts = append(stmts, s)
	}

	runes := []rune(script)
	for i := 0; i < len(runes); i++ {
		c := runes[i]

		switch {
		// Line comment: skip to end of line, keeping the newline as whitespace.
		case c == '-' && i+1 < len(runes) && runes[i+1] == '-':
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
			cur.WriteByte('\n')
			continue

		// Block comment: skip to the closing delimiter.
		case c == '/' && i+1 < len(runes) && runes[i+1] == '*':
			i += 2
			for i+1 < len(runes) && !(runes[i] == '*' && runes[i+1] == '/') {
				i++
			}
			i++ // land on '/'
			cur.WriteByte(' ')
			continue

		// String literal. '' is an escaped quote inside the literal.
		case c == '\'':
			cur.WriteRune(c)
			i++
			for i < len(runes) {
				if runes[i] == '\'' {
					if i+1 < len(runes) && runes[i+1] == '\'' {
						cur.WriteString("''")
						i += 2
						continue
					}
					cur.WriteRune('\'')
					break
				}
				cur.WriteRune(runes[i])
				i++
			}
			continue

		// Quoted identifier.
		case c == '"' || c == '`' || c == '[':
			closing := c
			if c == '[' {
				closing = ']'
			}
			cur.WriteRune(c)
			i++
			for i < len(runes) && runes[i] != closing {
				cur.WriteRune(runes[i])
				i++
			}
			if i < len(runes) {
				cur.WriteRune(runes[i])
			}
			continue
		}

		cur.WriteRune(c)

		// Track BEGIN … END so semicolons inside a trigger body are not terminators.
		if isWordBoundaryEnd(runes, i) {
			switch strings.ToUpper(trailingWord(cur.String())) {
			case "BEGIN":
				blockDepth++
			case "END":
				if blockDepth > 0 {
					blockDepth--
				}
			}
		}

		if c == ';' && blockDepth == 0 {
			flush()
		}
	}
	flush()
	return stmts
}

// isWordBoundaryEnd reports whether position i ends a bare word (the next rune is not a
// word character), so trailingWord is looking at a complete keyword.
func isWordBoundaryEnd(runes []rune, i int) bool {
	if !isWordRune(runes[i]) {
		return false
	}
	return i+1 >= len(runes) || !isWordRune(runes[i+1])
}

func isWordRune(r rune) bool {
	return r == '_' ||
		(r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9')
}

// trailingWord returns the bare word at the end of s.
func trailingWord(s string) string {
	end := len(s)
	i := end
	for i > 0 {
		r := rune(s[i-1])
		if !isWordRune(r) {
			break
		}
		i--
	}
	return s[i:end]
}

// addColumnRE matches `ALTER TABLE <table> ADD [COLUMN] <column>`, which SQLite accepts
// with or without the COLUMN keyword. Identifiers may be bare or quoted.
var addColumnRE = regexp.MustCompile(
	`(?is)^\s*ALTER\s+TABLE\s+(` + identPattern + `)\s+ADD\s+(?:COLUMN\s+)?(` + identPattern + `)`)

const identPattern = `"[^"]+"|` + "`[^`]+`" + `|\[[^\]]+\]|[A-Za-z_][A-Za-z0-9_$]*`

// unquoteIdent strips SQL identifier quoting so a name can be compared with
// pragma_table_info output.
func unquoteIdent(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return s
	}
	switch s[0] {
	case '"':
		if s[len(s)-1] == '"' {
			return strings.ReplaceAll(s[1:len(s)-1], `""`, `"`)
		}
	case '`':
		if s[len(s)-1] == '`' {
			return s[1 : len(s)-1]
		}
	case '[':
		if s[len(s)-1] == ']' {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// migrate applies any pending migrations, one transaction per migration.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at INTEGER NOT NULL
	)`); err != nil {
		return fmt.Errorf("storage: create schema_migrations: %w", err)
	}

	applied := map[int]bool{}
	rows, err := db.Query(`SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	migs, err := loadMigrations()
	if err != nil {
		return err
	}
	for _, m := range migs {
		if applied[m.version] {
			continue
		}
		if err := applyMigration(db, m); err != nil {
			return err
		}
	}
	return nil
}

// applyMigration runs one migration file in a single transaction.
//
// Migrations must be safe to re-run against a partially upgraded database (an older
// binary, or a crash mid-upgrade). That idempotency used to be implemented by executing
// each statement and swallowing the failure when the driver's error text contained
// "duplicate column name" — then recording the migration as applied regardless. Two
// problems with that: the guard depended on a driver's human-readable message, which is
// not part of any contract and can change with a dependency bump; and any OTHER error
// whose text happened to match was silently accepted, marking a migration applied when
// it was not.
//
// Idempotency is now decided by asking the schema. Before an ALTER TABLE … ADD COLUMN
// runs, pragma_table_info is consulted; if the column is already there, the statement is
// skipped deliberately. Every other error fails the migration and rolls it back.
func applyMigration(db *sql.DB, m migration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, stmt := range splitStatements(m.sql) {
		if match := addColumnRE.FindStringSubmatch(stmt); match != nil {
			table := unquoteIdent(match[1])
			column := unquoteIdent(match[2])
			exists, err := columnExists(tx, table, column)
			if err != nil {
				return fmt.Errorf("storage: migration %s: inspect %s.%s: %w", m.name, table, column, err)
			}
			if exists {
				continue // already upgraded — this is the idempotent path
			}
		}
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("storage: migration %s statement %q: %w", m.name, truncate(stmt, 60), err)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO schema_migrations(version, applied_at) VALUES(?, strftime('%s','now'))`,
		m.version,
	); err != nil {
		return fmt.Errorf("storage: record migration %s: %w", m.name, err)
	}
	return tx.Commit()
}

// columnExists reports whether table already has the named column. A table that does not
// exist yet reports false, which is correct: the CREATE TABLE earlier in the same
// migration will make the ALTER unnecessary or valid.
func columnExists(tx *sql.Tx, table, column string) (bool, error) {
	var n int
	err := tx.QueryRow(
		`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, column,
	).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// SchemaVersion returns the highest migration version that has been applied.
func SchemaVersion(db *sql.DB) (int, error) {
	var v int
	err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&v)
	return v, err
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
