package vault

import (
	"errors"
	"fmt"
	"time"

	"kosh/internal/audit"
	"kosh/internal/crypto"
)

// ErrWeakerKDF is returned when a re-key would reduce the vault's Argon2id cost. The cost
// is the only barrier protecting a copied vault.db against offline brute force, so
// lowering it is never done implicitly.
var ErrWeakerKDF = errors.New("vault: refusing to re-key with weaker KDF parameters")

// ErrBadKDFParams is returned for parameters outside the supported range.
var ErrBadKDFParams = errors.New("vault: KDF parameters out of range")

// KDFParams returns the Argon2id cost currently protecting the master password.
func (v *Vault) KDFParams() (crypto.KDFParams, error) {
	var p crypto.KDFParams
	err := v.db.SQL().QueryRow(
		`SELECT kdf_time,kdf_memory_kib,kdf_threads FROM vault_meta WHERE id=1`).
		Scan(&p.Time, &p.MemoryKiB, &p.Threads)
	if err != nil {
		return crypto.KDFParams{}, fmt.Errorf("vault: read kdf params: %w", err)
	}
	return p, nil
}

// RekeyKDF re-derives the master-password KEK under stronger Argon2id parameters and
// re-wraps the DEK beneath it.
//
// The DEK itself is unchanged, which is the point: no secret is re-encrypted, so there is
// nothing to re-encrypt incorrectly. Only the wrapping changes. That also means the audit
// MAC subkey is unchanged and every existing audit record stays verifiable.
//
// The recovery key is NOT touched and keeps working — it carries its own parameters since
// migration 0009.
//
// Requires the master password, not merely an unlocked vault: this rewrites the vault's
// key material, and an unattended unlocked window must not be enough to do that.
func (v *Vault) RekeyKDF(password []byte, params crypto.KDFParams) error {
	if !crypto.ValidKDFParams(params) {
		return ErrBadKDFParams
	}
	if err := v.VerifyPassword(password); err != nil {
		return err
	}

	current, err := v.KDFParams()
	if err != nil {
		return err
	}
	if !crypto.AtLeastAsStrong(current, params) {
		return ErrWeakerKDF
	}

	dek, _, err := v.dekCopy()
	if err != nil {
		return err
	}
	defer crypto.Zero(dek)

	newSalt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	newKEK := crypto.DeriveKey(password, newSalt, params)
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

	// Salt, verifier and wrapped DEK must move together: a verifier from one KEK with a
	// DEK wrapped under another leaves a vault that accepts the password and then fails
	// to unwrap. One transaction makes that combination unreachable.
	if _, err := tx.Exec(
		`UPDATE vault_meta SET kdf='argon2id', kdf_time=?, kdf_memory_kib=?, kdf_threads=?,
		        kdf_salt=?, verifier=?, dek_wrapped=?, updated_at=? WHERE id=1`,
		params.Time, params.MemoryKiB, params.Threads, newSalt, newVerifier, newWrapped,
		time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("vault: rekey kdf: %w", err)
	}
	detail := fmt.Sprintf("t=%d m=%dKiB p=%d -> t=%d m=%dKiB p=%d",
		current.Time, current.MemoryKiB, current.Threads,
		params.Time, params.MemoryKiB, params.Threads)
	if err := v.logAuditTx(tx, "rekey_kdf", "", audit.Allow, detail); err != nil {
		return fmt.Errorf("vault: audit rekey_kdf: %w", err)
	}
	return tx.Commit()
}
