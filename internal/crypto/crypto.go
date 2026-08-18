// Package crypto provides Kosh's cryptographic primitives.
//
// It implements only well-reviewed constructions from golang.org/x/crypto and the
// standard library:
//
//   - Argon2id      for password-based key derivation (KEK)
//   - XChaCha20-Poly1305 for authenticated encryption (AEAD)
//   - crypto/rand   for all salts, nonces and random keys
//   - crypto/subtle for constant-time comparison
//
// No custom cipher is defined here. This package knows nothing about SQLite, the UI,
// or the vault domain model; it is intentionally small and dependency-light so it can
// be reviewed and unit-tested in isolation.
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeyLen is the length in bytes of every symmetric key (KEK, DEK, RKEK, BK).
	KeyLen = 32
	// SaltLen is the length in bytes of an Argon2id salt.
	SaltLen = 16
	// NonceLen is the XChaCha20-Poly1305 nonce length (24 bytes -> random nonces safe).
	NonceLen = chacha20poly1305.NonceSizeX
	// Overhead is the Poly1305 authentication tag length added to each ciphertext.
	Overhead = chacha20poly1305.Overhead
)

// ErrDecrypt is returned when authentication/decryption fails. It is intentionally
// generic so callers cannot distinguish "wrong key" from "tampered ciphertext",
// avoiding an oracle.
var ErrDecrypt = errors.New("crypto: decryption failed")

// KDFParams captures the Argon2id cost parameters. They are stored in the vault header
// so they can be tuned upward over time without breaking existing vaults.
type KDFParams struct {
	Time      uint32 // number of passes
	MemoryKiB uint32 // memory cost in KiB
	Threads   uint8  // parallelism
}

// DefaultKDFParams returns a memory-hard baseline: 3 passes, 64 MiB, 4 threads.
func DefaultKDFParams() KDFParams {
	return KDFParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}
}

// RandomBytes returns n cryptographically secure random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("crypto: read random: %w", err)
	}
	return b, nil
}

// NewSalt returns a fresh random Argon2id salt.
func NewSalt() ([]byte, error) { return RandomBytes(SaltLen) }

// NewKey returns a fresh random 32-byte symmetric key (e.g. a DEK).
func NewKey() ([]byte, error) { return RandomBytes(KeyLen) }

// DeriveKey derives a 32-byte key from a password and salt using Argon2id with the
// supplied parameters. The returned key is suitable for use as a KEK.
func DeriveKey(password, salt []byte, p KDFParams) []byte {
	return argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, KeyLen)
}

// Encrypt performs XChaCha20-Poly1305 AEAD encryption. It generates a random 24-byte
// nonce and returns nonce||ciphertext||tag. The additionalData is authenticated but
// not encrypted; pass nil if none.
func Encrypt(key, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("crypto: key must be %d bytes", KeyLen)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new aead: %w", err)
	}
	nonce, err := RandomBytes(NonceLen)
	if err != nil {
		return nil, err
	}
	// Seal appends ciphertext+tag onto the nonce prefix.
	return aead.Seal(nonce, nonce, plaintext, additionalData), nil
}

// Decrypt reverses Encrypt. The blob must be nonce||ciphertext||tag. additionalData
// must match what was passed to Encrypt. On any failure it returns ErrDecrypt.
func Decrypt(key, blob, additionalData []byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("crypto: key must be %d bytes", KeyLen)
	}
	if len(blob) < NonceLen+Overhead {
		return nil, ErrDecrypt
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new aead: %w", err)
	}
	nonce, ct := blob[:NonceLen], blob[NonceLen:]
	pt, err := aead.Open(nil, nonce, ct, additionalData)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// WrapKey encrypts (wraps) a key under a wrapping key using AEAD. Used to wrap the DEK
// under the KEK / RKEK in the envelope key hierarchy.
func WrapKey(wrappingKey, keyToWrap []byte) ([]byte, error) {
	if len(keyToWrap) != KeyLen {
		return nil, fmt.Errorf("crypto: key to wrap must be %d bytes", KeyLen)
	}
	return Encrypt(wrappingKey, keyToWrap, []byte("localvault/dek-wrap"))
}

// UnwrapKey reverses WrapKey. Returns ErrDecrypt on wrong wrapping key or tampering.
func UnwrapKey(wrappingKey, wrapped []byte) ([]byte, error) {
	return Decrypt(wrappingKey, wrapped, []byte("localvault/dek-wrap"))
}

// verifierPlaintext is a fixed marker encrypted under the KEK so that a typed password
// can be validated (the AEAD tag verifies) without exposing the DEK.
var verifierPlaintext = []byte("LOCALVAULT-VERIFY-v1")

// MakeVerifier encrypts the fixed verifier marker under kek.
func MakeVerifier(kek []byte) ([]byte, error) {
	return Encrypt(kek, verifierPlaintext, []byte("localvault/verifier"))
}

// CheckVerifier returns true if the supplied kek correctly decrypts the verifier.
// Comparison is constant-time.
func CheckVerifier(kek, verifier []byte) bool {
	pt, err := Decrypt(kek, verifier, []byte("localvault/verifier"))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(pt, verifierPlaintext) == 1
}

// KeyedHash computes an HMAC-style keyed hash of data for duplicate detection. It is
// not reversible and, because it is keyed with a vault-scoped subkey, resists offline
// dictionary attacks on the stored hashes. Implemented via AEAD over a fixed nonce is
// avoided; we use BLAKE2b keyed hashing.
func KeyedHash(key, data []byte) []byte {
	// Use the AEAD key schedule's underlying primitive indirectly is overkill; a keyed
	// BLAKE2b is the right tool and is available in x/crypto.
	return blake2bKeyed(key, data)
}

// Zero overwrites b with zeros. Best-effort defense-in-depth for key/plaintext buffers
// (Go's GC may still have copied memory; documented in docs/THREAT_MODEL.md).
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
