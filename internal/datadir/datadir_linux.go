//go:build linux

package datadir

import (
	"fmt"
	"os"
	"path/filepath"
)

func baseDir() (string, error) {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return xdg, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("datadir: home dir: %w", err)
	}
	return filepath.Join(home, ".local", "share"), nil
}
