// Package health computes a security health score for each stored secret and detects
// the four actionable conditions documented in docs/THREAT_MODEL.md T7:
//
//   - Expired:   expires_at is set and in the past.
//   - Upcoming:  expires_at is within the configured warning window (default 14 days).
//   - Unused:    last_used_at has never been set or is older than the threshold.
//   - Old:       created_at / updated_at is older than the rotation threshold.
//   - Duplicate: another secret has the same value_hash (same underlying credential).
//
// The health engine never decrypts secret values. It reads only the non-secret
// metadata columns (timestamps, value_hash) to compute its signals.
package health

import (
	"database/sql"
	"fmt"
	"time"
)

// Status classifies a secret's health.
type Status string

const (
	StatusHealthy  Status = "healthy"
	StatusWarning  Status = "warning"
	StatusCritical Status = "critical"
)

// Flag is a single health signal for a secret.
type Flag string

const (
	FlagExpired   Flag = "expired"
	FlagUpcoming  Flag = "expiring_soon"
	FlagUnused    Flag = "unused"
	FlagOld       Flag = "old"
	FlagDuplicate Flag = "duplicate"
)

// Config holds the thresholds used to compute health. Callers can load this from the
// settings table; sane defaults are provided by DefaultConfig.
type Config struct {
	ExpiringSoonDays int // flag as upcoming if expiry is within N days (default 14)
	UnusedDays       int // flag as unused if last_used_at > N days ago (default 90)
	OldDays          int // flag as old if updated_at > N days ago (default 180)
}

// DefaultConfig returns the default health thresholds.
func DefaultConfig() Config {
	return Config{ExpiringSoonDays: 14, UnusedDays: 90, OldDays: 180}
}

// SecretHealth is the computed health for one secret.
type SecretHealth struct {
	SecretID   int64
	Alias      string
	Status     Status
	Flags      []Flag
	Score      int // 0 (critical) … 100 (perfect)
	DupAliases []string // aliases of secrets with the same value_hash
}

// Score computes health for all non-archived secrets in the vault. It never decrypts
// any value; it only reads alias, value_hash, and timestamp columns.
func Score(db *sql.DB, cfg Config) ([]SecretHealth, error) {
	now := time.Now().Unix()
	warnBefore := now + int64(cfg.ExpiringSoonDays*86400)

	type row struct {
		id         int64
		alias      string
		valueHash  []byte
		createdAt  int64
		updatedAt  int64
		lastUsedAt *int64
		expiresAt  *int64
	}

	rows, err := db.Query(
		`SELECT id, alias, value_hash, created_at, updated_at, last_used_at, expires_at
		   FROM secrets WHERE is_archived=0`)
	if err != nil {
		return nil, fmt.Errorf("health: query: %w", err)
	}
	defer rows.Close()

	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.alias, &r.valueHash, &r.createdAt, &r.updatedAt, &r.lastUsedAt, &r.expiresAt); err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	hashToAliases := map[string][]string{}
	for _, r := range all {
		k := fmt.Sprintf("%x", r.valueHash)
		hashToAliases[k] = append(hashToAliases[k], r.alias)
	}

	out := make([]SecretHealth, 0, len(all))
	unusedThreshold := now - int64(cfg.UnusedDays*86400)
	oldThreshold := now - int64(cfg.OldDays*86400)

	for _, r := range all {
		sh := SecretHealth{SecretID: r.id, Alias: r.alias}

		if r.expiresAt != nil && *r.expiresAt <= now {
			sh.Flags = append(sh.Flags, FlagExpired)
		} else if r.expiresAt != nil && *r.expiresAt <= warnBefore {
			sh.Flags = append(sh.Flags, FlagUpcoming)
		}

		if r.lastUsedAt == nil || *r.lastUsedAt < unusedThreshold {
			sh.Flags = append(sh.Flags, FlagUnused)
		}

		if r.updatedAt < oldThreshold {
			sh.Flags = append(sh.Flags, FlagOld)
		}

		k := fmt.Sprintf("%x", r.valueHash)
		if len(hashToAliases[k]) > 1 {
			sh.Flags = append(sh.Flags, FlagDuplicate)
			for _, a := range hashToAliases[k] {
				if a != r.alias {
					sh.DupAliases = append(sh.DupAliases, a)
				}
			}
		}

		sh.Score = computeScore(sh.Flags)
		sh.Status = statusFromScore(sh.Score)
		out = append(out, sh)
	}
	return out, nil
}

// computeScore returns 0–100. Every critical flag (expired, duplicate) costs 40 pts;
// every warning flag (upcoming, unused, old) costs 20 pts.
func computeScore(flags []Flag) int {
	score := 100
	for _, f := range flags {
		switch f {
		case FlagExpired, FlagDuplicate:
			score -= 40
		case FlagUpcoming, FlagUnused, FlagOld:
			score -= 20
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func statusFromScore(score int) Status {
	switch {
	case score >= 80:
		return StatusHealthy
	case score >= 40:
		return StatusWarning
	default:
		return StatusCritical
	}
}
