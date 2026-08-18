//go:build darwin

package datadir

import (
	"fmt"
	"os"
	"path/filepath"
)

func baseDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("datadir: home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support"), nil
}
