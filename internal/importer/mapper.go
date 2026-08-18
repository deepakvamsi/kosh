package importer

import (
	"strconv"
	"strings"
)

// ColMap tells the importer which column index in the spreadsheet maps to which
// ImportRow field. Set a field to -1 to indicate "not present".
type ColMap struct {
	Alias       int // required
	Value       int // required — the secret value (API key, password, …)
	ProviderKey int // optional; defaults to "custom"
	Environment int // optional; defaults to "dev"
	Description int // optional
	ExpiresAt   int // optional — ISO date string "2025-12-31" or Unix seconds string
}

// DefaultColMap tries to auto-detect column positions from the header row using
// common column names. Returns -1 for columns that could not be auto-detected.
func DefaultColMap(headers []string) ColMap {
	m := ColMap{Alias: -1, Value: -1, ProviderKey: -1, Environment: -1, Description: -1, ExpiresAt: -1}
	for i, h := range headers {
		h = strings.ToLower(strings.TrimSpace(h))
		switch h {
		case "alias", "name", "key", "key_name", "secret_name", "variable":
			if m.Alias == -1 {
				m.Alias = i
			}
		case "value", "secret", "secret_value", "password", "token", "api_key", "apikey":
			if m.Value == -1 {
				m.Value = i
			}
		case "provider", "service", "provider_key", "type":
			if m.ProviderKey == -1 {
				m.ProviderKey = i
			}
		case "environment", "env", "stage":
			if m.Environment == -1 {
				m.Environment = i
			}
		case "description", "desc", "notes", "note", "comment":
			if m.Description == -1 {
				m.Description = i
			}
		case "expires", "expires_at", "expiry", "expiry_date", "expiration":
			if m.ExpiresAt == -1 {
				m.ExpiresAt = i
			}
		}
	}
	return m
}

// Status of a single import row.
type RowStatus string

const (
	StatusPending   RowStatus = "pending"
	StatusDuplicate RowStatus = "duplicate"
	StatusInvalid   RowStatus = "invalid"
	StatusImported  RowStatus = "imported"
	StatusSkipped   RowStatus = "skipped"
)

// ImportRow is one prospective secret parsed from the source file.
type ImportRow struct {
	SourceRow   int
	Alias       string
	Value       string
	ProviderKey string
	Environment string
	Description string
	ExpiresAt   *int64
	Status      RowStatus
	StatusNote  string
}

// MapColumns converts a RawTable into a slice of ImportRows using the provided
// column mapping. Rows that are missing the required Alias or Value columns are
// marked StatusInvalid.
func MapColumns(table RawTable, cm ColMap) ([]ImportRow, []ParseError) {
	var rows []ImportRow
	var errs []ParseError

	for i, raw := range table.Rows {
		rowNum := i + 2 // 1-indexed, row 1 = header
		row := ImportRow{
			SourceRow:   rowNum,
			ProviderKey: "custom",
			Environment: "dev",
			Status:      StatusPending,
		}

		if cm.Alias >= 0 && cm.Alias < len(raw) {
			row.Alias = strings.TrimSpace(raw[cm.Alias])
		}
		if cm.Value >= 0 && cm.Value < len(raw) {
			row.Value = strings.TrimSpace(raw[cm.Value])
		}
		if cm.ProviderKey >= 0 && cm.ProviderKey < len(raw) {
			if v := strings.TrimSpace(raw[cm.ProviderKey]); v != "" {
				row.ProviderKey = normalizeProvider(v)
			}
		}
		if cm.Environment >= 0 && cm.Environment < len(raw) {
			if v := strings.TrimSpace(raw[cm.Environment]); v != "" {
				row.Environment = normalizeEnv(v)
			}
		}
		if cm.Description >= 0 && cm.Description < len(raw) {
			row.Description = strings.TrimSpace(raw[cm.Description])
		}
		if cm.ExpiresAt >= 0 && cm.ExpiresAt < len(raw) {
			if ts, ok := parseExpiry(strings.TrimSpace(raw[cm.ExpiresAt])); ok {
				row.ExpiresAt = &ts
			}
		}

		// Sanitise alias first (uppercase, replace spaces/dashes with underscores), then
		// validate — otherwise an all-symbol alias like "!!!" passes the emptiness check
		// but sanitises down to "" and would reach the vault as an empty alias.
		row.Alias = sanitizeAlias(row.Alias)

		if row.Alias == "" {
			errs = append(errs, ParseError{Row: rowNum, Message: "alias/name column is empty or has no usable characters"})
			row.Status = StatusInvalid
			row.StatusNote = "missing alias"
		} else if row.Value == "" {
			row.Status = StatusInvalid
			row.StatusNote = "missing value"
		}

		rows = append(rows, row)
	}
	return rows, errs
}

func sanitizeAlias(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			out = append(out, c)
		} else if c == ' ' || c == '-' || c == '.' {
			out = append(out, '_')
		}
	}
	return string(out)
}

// knownProviders maps common strings to the provider keys seeded in the DB.
var knownProviders = map[string]string{
	"aws": "aws", "amazon": "aws", "amazon web services": "aws",
	"gcp": "gcp", "google cloud": "gcp", "google": "gcp",
	"azure": "azure", "microsoft azure": "azure",
	"openai": "openai", "open ai": "openai",
	"anthropic": "anthropic", "claude": "anthropic",
	"gemini": "gemini", "google gemini": "gemini",
	"grok": "xai", "xai": "xai",
	"mistral":    "mistral",
	"groq":       "groq",
	"deepseek":   "deepseek",
	"openrouter": "openrouter",
	"github":     "github",
	"gitlab":     "gitlab",
	"bitbucket":  "bitbucket",
	"cursor":     "cursor",
	"replit":     "replit",
	"vercel":     "vercel",
	"cloudflare": "cloudflare",
	"docker":     "docker",
	"postgres":   "postgresql", "postgresql": "postgresql",
	"mongo": "mongodb", "mongodb": "mongodb",
	"redis": "redis",
}

func normalizeProvider(s string) string {
	k := strings.ToLower(strings.TrimSpace(s))
	if v, ok := knownProviders[k]; ok {
		return v
	}
	return "custom"
}

func normalizeEnv(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "prod", "production", "prd":
		return "prod"
	case "staging", "stage", "stg":
		return "staging"
	case "qa", "test", "testing":
		return "qa"
	default:
		return "dev"
	}
}

func parseExpiry(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	// Treat the value as Unix seconds ONLY when the entire string is a positive integer.
	// Using fmt.Sscanf("%d") here was a bug: it greedily consumed the leading digits of an
	// ISO date ("2025-12-31" -> 2025) and reported success, so every date parsed as epoch
	// 1970 and the secret looked already-expired. strconv.ParseInt requires the whole
	// string to be numeric, so real dates now fall through to the layout parsers below.
	if ts, err := strconv.ParseInt(s, 10, 64); err == nil && ts > 0 {
		return ts, true
	}
	formats := []string{"2006-01-02", "01/02/2006", "02-01-2006", "2006/01/02"}
	for _, f := range formats {
		if t, err := parseDateTime(s, f); err == nil {
			return t, true
		}
	}
	return 0, false
}
