package vault

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"kosh/internal/audit"
)

// ErrTooManyAttempts is returned by Unlock when the vault is temporarily locked out after
// repeated failed attempts. It is a throttle, not a permanent lock: the wait is bounded
// (see backoffFor) and the recovery key always bypasses it. Call LockoutRemaining to show
// the seconds left. Note this defends the running app only — an attacker who copies the
// database can brute-force it offline, where the sole barrier is the Argon2id cost.
var ErrTooManyAttempts = errors.New("vault: too many failed unlock attempts")

// freeUnlockAttempts is the number of consecutive wrong passwords allowed with no delay,
// so ordinary typos never cost the legitimate user a wait.
const freeUnlockAttempts = 4

const (
	settingUnlockFails = "unlock_fails"
	settingLockedUntil = "unlock_locked_until"
)

// backoffFor returns how long the vault stays locked after `fails` consecutive failures.
// The schedule escalates and is capped so a forgetful user is never permanently locked
// out (and can always fall back to the recovery key).
func backoffFor(fails int) time.Duration {
	switch {
	case fails <= freeUnlockAttempts:
		return 0
	case fails == 5:
		return 5 * time.Second
	case fails == 6:
		return 15 * time.Second
	case fails == 7:
		return 30 * time.Second
	case fails == 8:
		return 60 * time.Second
	case fails == 9:
		return 5 * time.Minute
	default:
		return 15 * time.Minute // cap
	}
}

func (v *Vault) readLockout() (fails int, until int64) {
	var fs, un sql.NullString
	v.db.SQL().QueryRow(`SELECT value FROM settings WHERE key=?`, settingUnlockFails).Scan(&fs)
	v.db.SQL().QueryRow(`SELECT value FROM settings WHERE key=?`, settingLockedUntil).Scan(&un)
	if fs.Valid {
		fails, _ = strconv.Atoi(fs.String)
	}
	if un.Valid {
		until, _ = strconv.ParseInt(un.String, 10, 64)
	}
	return fails, until
}

func (v *Vault) writeSetting(key, val string) error {
	_, err := v.db.SQL().Exec(
		`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, val)
	return err
}

// LockoutRemaining returns the seconds the vault is currently locked out for, or 0 if an
// unlock may be attempted now.
func (v *Vault) LockoutRemaining() int {
	_, until := v.readLockout()
	rem := until - time.Now().Unix()
	if rem <= 0 {
		return 0
	}
	return int(rem)
}

// recordUnlockFailure increments the persisted failure counter and, once past the free
// attempts, sets a lockout window per backoffFor. Persisting to the DB (not memory) is
// deliberate: restarting the app must not reset the throttle.
func (v *Vault) recordUnlockFailure() {
	fails, _ := v.readLockout()
	fails++
	var until int64
	if d := backoffFor(fails); d > 0 {
		until = time.Now().Unix() + int64(d.Seconds())
		_ = audit.Log(v.db.SQL(), v.actor, "unlock_lockout", "", audit.Deny,
			fmt.Sprintf("%d consecutive failures; locked for %s", fails, d))
	}
	_ = v.writeSetting(settingUnlockFails, strconv.Itoa(fails))
	_ = v.writeSetting(settingLockedUntil, strconv.FormatInt(until, 10))
}

// resetUnlockFailures clears the throttle after a successful unlock or recovery.
func (v *Vault) resetUnlockFailures() {
	_ = v.writeSetting(settingUnlockFails, "0")
	_ = v.writeSetting(settingLockedUntil, "0")
}
