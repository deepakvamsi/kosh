// Package storage is Kosh's persistence layer over SQLite (pure-Go driver
// modernc.org/sqlite, no CGO). It stores only ciphertext and non-secret metadata; it
// never sees or stores plaintext secrets or the master password.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB with Kosh-specific helpers.
type DB struct {
	sql *sql.DB
}

// Open opens (creating if necessary) the SQLite database at path, hardens file
// permissions to the current OS user, enables foreign keys + WAL, and runs migrations.
func Open(path string) (*DB, error) {
	// _pragma options configure the connection on open.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)", path)
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open: %w", err)
	}
	sqldb.SetMaxOpenConns(1) // simplify WAL + write serialization for a desktop app
	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("storage: ping: %w", err)
	}
	if err := migrate(sqldb); err != nil {
		sqldb.Close()
		return nil, err
	}
	if path != ":memory:" {
		if err := hardenPermissions(path); err != nil {
			sqldb.Close()
			return nil, err
		}
	}
	db := &DB{sql: sqldb}
	if err := db.seedProviders(); err != nil {
		sqldb.Close()
		return nil, err
	}
	return db, nil
}

// OpenMemory opens an in-memory database (used by tests).
func OpenMemory() (*DB, error) { return Open(":memory:") }

// Close closes the underlying database.
func (d *DB) Close() error { return d.sql.Close() }

// SQL exposes the underlying *sql.DB for advanced callers (vault package).
func (d *DB) SQL() *sql.DB { return d.sql }

func now() int64 { return time.Now().Unix() }

func (d *DB) seedProviders() error {
	type p struct {
		key, name, category string
	}
	builtins := []p{
		{"aws", "Amazon Web Services", "cloud"},
		{"gcp", "Google Cloud Platform", "cloud"},
		{"azure", "Microsoft Azure", "cloud"},
		{"openai", "OpenAI", "ai"},
		{"anthropic", "Anthropic", "ai"},
		{"gemini", "Google Gemini", "ai"},
		{"xai", "Grok / xAI", "ai"},
		{"mistral", "Mistral", "ai"},
		{"groq", "Groq", "ai"},
		{"deepseek", "DeepSeek", "ai"},
		{"openrouter", "OpenRouter", "ai"},
		{"github", "GitHub", "vcs"},
		{"gitlab", "GitLab", "vcs"},
		{"bitbucket", "Bitbucket", "vcs"},
		{"cursor", "Cursor", "platform"},
		{"replit", "Replit", "platform"},
		{"vercel", "Vercel", "platform"},
		{"cloudflare", "Cloudflare", "platform"},
		{"docker", "Docker", "platform"},
		{"postgresql", "PostgreSQL", "db"},
		{"mongodb", "MongoDB", "db"},
		{"redis", "Redis", "db"},
		{"custom", "Custom", "custom"},
	}
	ctx := context.Background()
	for _, b := range builtins {
		_, err := d.sql.ExecContext(ctx,
			`INSERT OR IGNORE INTO providers(key,name,category,is_builtin,created_at) VALUES(?,?,?,1,?)`,
			b.key, b.name, b.category, now())
		if err != nil {
			return fmt.Errorf("storage: seed provider %s: %w", b.key, err)
		}
	}
	return nil
}
