//go:build !windows && !linux && !darwin

package datadir

import "os"

func baseDir() (string, error) {
	if home, err := os.UserHomeDir(); err == nil {
		return home, nil
	}
	return "", ErrUnknownPlatform
}
