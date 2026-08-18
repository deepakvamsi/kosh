package importer

import (
	"fmt"
	"strings"
	"time"
)

func parseDateTime(s, layout string) (int64, error) {
	s = strings.TrimSpace(s)
	t, err := time.Parse(layout, s)
	if err != nil {
		return 0, fmt.Errorf("parse date: %w", err)
	}
	return t.Unix(), nil
}
