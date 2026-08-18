package vault

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"kosh/internal/audit"
	"kosh/internal/crypto"
)

var (
	// ErrNoRecoveryKey is returned by RecoverWithKey when no recovery key was ever set.
	ErrNoRecoveryKey = errors.New("vault: no recovery key configured")
	// ErrWrongRecoveryKey is returned when the supplied recovery code does not unwrap the DEK.
	ErrWrongRecoveryKey = errors.New("vault: invalid recovery key")
)

// recoveryEntropyBytes is the size of the random recovery secret (160 bits). It is shown
// to the user once, formatted as a grouped Base32 code, and is strong enough to resist
// brute force even though an Argon2id KDF also guards it.
const recoveryEntropyBytes = 20

// recoveryEnc is unpadded, uppercase Base32 (RFC 4648) — a human-friendly alphabet with
// no lookalike-prone lowercase and no padding characters.
var recoveryEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateRecoveryKey creates (or replaces) a recovery key for an unlocked vault. It
// wraps the current DEK under a key derived from a fresh random recovery code and stores
// that wrapped copy (dek_recovery) alongside its salt (recovery_salt). The returned code
// is the ONLY time the caller can see it — it is never stored in recoverable form. With
// it, a user who has forgotten the master password can re-key the vault via
// RecoverWithKey. Requires the vault to be unlocked.
func (v *Vault) GenerateRecoveryKey() (string, error) {
	dek, _, err := v.dekCopy()
	if err != nil {
		return "", err
	}
	defer crypto.Zero(dek)

	// Reuse the vault's own Argon2id cost parameters for the recovery KDF.
	var p crypto.KDFParams
	if err := v.db.SQL().QueryRow(
		`SELECT kdf_time,kdf_memory_kib,kdf_threads FROM vault_meta WHERE id=1`).
		Scan(&p.Time, &p.MemoryKiB, &p.Threads); err != nil {
		return "", fmt.Errorf("vault: read kdf params: %w", err)
	}

	raw, err := crypto.RandomBytes(recoveryEntropyBytes)
	if err != nil {
		return "", err
	}
	defer crypto.Zero(raw)
	normalized := recoveryEnc.EncodeToString(raw) // canonical secret (no dashes)

	salt, err := crypto.NewSalt()
	if err != nil {
		return "", err
	}
	rkek := crypto.DeriveKey([]byte(normalized), salt, p)
	defer crypto.Zero(rkek)
	wrapped, err := crypto.WrapKey(rkek, dek)
	if err != nil {
		return "", err
	}

	tx, err := v.db.SQL().Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`UPDATE vault_meta SET recovery_salt=?, dek_recovery=?, updated_at=? WHERE id=1`,
		salt, wrapped, time.Now().Unix()); err != nil {
		return "", fmt.Errorf("vault: store recovery key: %w", err)
	}
	if err := audit.LogTx(tx, v.actor, "recovery_key_set", "", audit.Allow, ""); err != nil {
		return "", fmt.Errorf("vault: audit recovery_key_set: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return groupRecoveryCode(normalized), nil
}

// HasRecoveryKey reports whether a recovery key has been configured for this vault.
func (v *Vault) HasRecoveryKey() (bool, error) {
	var recSalt, dekRec []byte
	err := v.db.SQL().QueryRow(
		`SELECT recovery_salt, dek_recovery FROM vault_meta WHERE id=1`).Scan(&recSalt, &dekRec)
	if err != nil {
		return false, err
	}
	return len(recSalt) > 0 && len(dekRec) > 0, nil
}

// RecoverWithKey unlocks the vault using a recovery code instead of the master password,
// then re-keys the vault under newPassword: it derives a fresh KEK, re-wraps the DEK, and
// replaces the stored salt/verifier/wrapped-DEK so subsequent unlocks use the new
// password. On success the vault is left unlocked. The recovery key itself is preserved
// (it still unwraps the same DEK), so it keeps working until explicitly regenerated.
func (v *Vault) RecoverWithKey(recoveryCode string, newPassword []byte) error {
	init, err := v.IsInitialized()
	if err != nil {
		return err
	}
	if !init {
		return ErrNotInitialized
	}

	var (
		p       crypto.KDFParams
		recSalt []byte
		dekRec  []byte
	)
	if err := v.db.SQL().QueryRow(
		`SELECT kdf_time,kdf_memory_kib,kdf_threads,recovery_salt,dek_recovery FROM vault_meta WHERE id=1`).
		Scan(&p.Time, &p.MemoryKiB, &p.Threads, &recSalt, &dekRec); err != nil {
		return fmt.Errorf("vault: read meta: %w", err)
	}
	if len(recSalt) == 0 || len(dekRec) == 0 {
		return ErrNoRecoveryKey
	}

	normalized := normalizeRecoveryCode(recoveryCode)
	if normalized == "" {
		return ErrWrongRecoveryKey
	}
	rkek := crypto.DeriveKey([]byte(normalized), recSalt, p)
	defer crypto.Zero(rkek)
	dek, err := crypto.UnwrapKey(rkek, dekRec)
	if err != nil {
		_ = audit.Log(v.db.SQL(), v.actor, "recover", "", audit.Deny, "invalid recovery key")
		return ErrWrongRecoveryKey
	}
	defer crypto.Zero(dek)

	// Re-key under the new master password.
	params := crypto.DefaultKDFParams()
	newSalt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	newKEK := crypto.DeriveKey(newPassword, newSalt, params)
	defer crypto.Zero(newKEK)
	newWrapped, err := crypto.WrapKey(newKEK, dek)
	if err != nil {
		return err
	}
	newVerifier, err := crypto.MakeVerifier(newKEK)
	if err != nil {
		return err
	}

	tx, err := v.db.SQL().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`UPDATE vault_meta SET kdf='argon2id', kdf_time=?, kdf_memory_kib=?, kdf_threads=?,
		        kdf_salt=?, verifier=?, dek_wrapped=?, updated_at=? WHERE id=1`,
		params.Time, params.MemoryKiB, params.Threads, newSalt, newVerifier, newWrapped,
		time.Now().Unix()); err != nil {
		return fmt.Errorf("vault: rekey: %w", err)
	}
	if err := audit.LogTx(tx, v.actor, "recover", "", audit.Allow, ""); err != nil {
		return fmt.Errorf("vault: audit recover: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	// Recovery is the escape hatch from a lockout — clear the throttle so the freshly
	// re-keyed password isn't blocked by a stale lockout window.
	v.resetUnlockFailures()

	// Leave the vault unlocked with a private copy of the DEK.
	v.mu.Lock()
	v.dek = append([]byte(nil), dek...)
	v.hmac = crypto.KeyedHash(v.dek, []byte("localvault/duplicate-subkey"))
	v.touch()
	v.mu.Unlock()
	return nil
}

// groupRecoveryCode formats the canonical Base32 secret into dash-separated groups of
// four for legibility, e.g. "JBSW-Y3DP-EHPK-3PXP-...".
func groupRecoveryCode(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// normalizeRecoveryCode reverses groupRecoveryCode's formatting: it strips dashes and
// whitespace and uppercases, yielding the canonical secret the KDF was derived from.
func normalizeRecoveryCode(code string) string {
	repl := strings.NewReplacer("-", "", " ", "", "\t", "", "\n", "", "\r", "")
	return strings.ToUpper(repl.Replace(strings.TrimSpace(code)))
}
