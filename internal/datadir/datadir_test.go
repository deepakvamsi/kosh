package datadir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveReturnsNonEmpty(t *testing.T) {
	dir, err := Resolve()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if dir == "" {
		t.Fatal("expected non-empty data dir")
	}
	if !strings.Contains(dir, "Kosh") {
		t.Fatalf("expected dir to contain 'Kosh', got %q", dir)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("directory was not created: %v", err)
	}
}

func TestDBPathEndsInVaultDB(t *testing.T) {
	p, err := DBPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p, "vault.db") {
		t.Fatalf("expected path ending in vault.db, got %q", p)
	}
}

func TestMigrateLegacyMovesVault(t *testing.T) {
	base := t.TempDir()
	legacy := filepath.Join(base, legacyAppName)
	newDir := filepath.Join(base, appName)
	for _, d := range []string{legacy, newDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Seed a legacy vault with a WAL sibling.
	if err := os.WriteFile(filepath.Join(legacy, "vault.db"), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "vault.db-wal"), []byte("wal"), 0o600); err != nil {
		t.Fatal(err)
	}

	migrateLegacy(base, newDir)

	if _, err := os.Stat(filepath.Join(newDir, "vault.db")); err != nil {
		t.Fatal("vault.db was not migrated into the new dir")
	}
	if _, err := os.Stat(filepath.Join(newDir, "vault.db-wal")); err != nil {
		t.Fatal("vault.db-wal was not migrated into the new dir")
	}
	if _, err := os.Stat(filepath.Join(legacy, "vault.db")); !os.IsNotExist(err) {
		t.Fatal("legacy vault.db should have been moved, not copied")
	}
}

func TestMigrateLegacyNoClobber(t *testing.T) {
	base := t.TempDir()
	legacy := filepath.Join(base, legacyAppName)
	newDir := filepath.Join(base, appName)
	for _, d := range []string{legacy, newDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Both locations hold a vault — the existing (new) one must be left untouched.
	if err := os.WriteFile(filepath.Join(legacy, "vault.db"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(newDir, "vault.db"), []byte("current"), 0o600); err != nil {
		t.Fatal(err)
	}

	migrateLegacy(base, newDir)

	got, err := os.ReadFile(filepath.Join(newDir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "current" {
		t.Fatalf("existing vault was clobbered: got %q, want %q", got, "current")
	}
}
