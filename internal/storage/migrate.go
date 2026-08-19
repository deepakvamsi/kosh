package storage

import (
	"database/sql"
	"embed"
	"fmt"
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
		b, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: e.Name(), sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// splitStatements splits a SQL script into individual non-empty statements,
// stripping line comments and splitting on semicolons. This lets each ALTER TABLE
// run in its own Exec call so a failing ALTER on an already-upgraded column does
// not abort the whole migration.
func splitStatements(script string) []string {
	var stmts []string
	var cur strings.Builder
	for _, line := range strings.Split(script, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || trimmed == "" {
			continue
		}
		cur.WriteString(line)
		cur.WriteByte('\n')
		if strings.Contains(line, ";") {
			s := strings.TrimSpace(cur.String())
			if s != "" && s != ";" {
				stmts = append(stmts, s)
			}
			cur.Reset()
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts
}

// migrate applies any pending migrations inside a single transaction per migration.
// ALTER TABLE statements that add columns are executed individually and any
// "duplicate column name" error is silently ignored — this makes every migration
// safe to re-run against a database that was partially upgraded (e.g. from a crash
// mid-migration or from an older binary that applied some statements manually).
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

// applyMigration runs one migration file. Each SQL statement is executed
// individually. ALTER TABLE … ADD COLUMN errors caused by duplicate columns are
// silently ignored so that schema solidification migrations are idempotent.
func applyMigration(db *sql.DB, m migration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, stmt := range splitStatements(m.sql) {
		if _, execErr := tx.Exec(stmt); execErr != nil {
			isAlter := strings.Contains(strings.ToUpper(stmt), "ALTER TABLE") &&
				strings.Contains(strings.ToUpper(stmt), "ADD COLUMN")
			isDuplicate := strings.Contains(execErr.Error(), "duplicate column name") ||
				strings.Contains(execErr.Error(), "already exists")
			if isAlter && isDuplicate {
				continue
			}
			return fmt.Errorf("storage: migration %s statement %q: %w", m.name, stmt[:min(60, len(stmt))], execErr)
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

// SchemaVersion returns the highest migration version that has been applied.
func SchemaVersion(db *sql.DB) (int, error) {
	var v int
	err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&v)
	return v, err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
