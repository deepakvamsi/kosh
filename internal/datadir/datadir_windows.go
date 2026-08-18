//go:build windows

package datadir

import (
	"fmt"
	"os"
)

func baseDir() (string, error) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return "", fmt.Errorf("datadir: %%APPDATA%% is not set")
	}
	return appdata, nil
}
