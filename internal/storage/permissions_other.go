//go:build !windows

package storage

import "os"

// hardenPermissions restricts the database file to owner-only (0600) on non-Windows
// platforms. The Windows implementation lives in permissions_windows.go.
func hardenPermissions(path string) error {
	return os.Chmod(path, 0o600)
}
