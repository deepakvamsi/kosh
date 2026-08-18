// Package datadir resolves the platform-specific directory where Kosh stores
// its data (encrypted database and backups). It follows OS conventions:
//
//   - Windows: %APPDATA%\Kosh
//   - Linux:   $XDG_DATA_HOME/Kosh  (falls back to $HOME/.local/share/Kosh)
//   - macOS:   $HOME/Library/Application Support/Kosh
//
// The directory is created with 0700 permissions if it does not exist.
package datadir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const appName = "Kosh"

// legacyAppName is the data-directory name used before the app was renamed to Kosh.
// One-time migration moves an existing vault out of it so the rename never strands data.
const legacyAppName = "LocalVault"

// ErrUnknownPlatform is returned when the OS data directory cannot be resolved.
var ErrUnknownPlatform = errors.New("datadir: cannot determine user data directory on this platform")

// Resolve returns the path of the application data directory, creating it if needed.
func Resolve() (string, error) {
	base, err := baseDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, appName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("datadir: create %s: %w", dir, err)
	}
	migrateLegacy(base, dir)
	return dir, nil
}

// migrateLegacy moves a pre-rename vault from the old data directory into the current
// one the first time Kosh runs after the rename, so an existing local vault is not
// stranded. It is best-effort and conservative: it only acts when the new directory has
// no vault yet and the legacy directory does, and any per-file error is left as-is
// (the app then simply starts with whatever made it across).
func migrateLegacy(base, newDir string) {
	legacy := filepath.Join(base, legacyAppName)
	if legacy == newDir {
		return
	}
	// Don't touch anything if the new location already holds a vault.
	if _, err := os.Stat(filepath.Join(newDir, "vault.db")); err == nil {
		return
	}
	// Nothing to migrate unless the legacy location actually holds a vault.
	if _, err := os.Stat(filepath.Join(legacy, "vault.db")); err != nil {
		return
	}
	// Move the database and its WAL/SHM siblings so no committed data is left behind.
	for _, name := range []string{"vault.db", "vault.db-wal", "vault.db-shm"} {
		src := filepath.Join(legacy, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		_ = os.Rename(src, filepath.Join(newDir, name))
	}
}

// DBPath returns the path to the vault database file.
func DBPath() (string, error) {
	dir, err := Resolve()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vault.db"), nil
}
