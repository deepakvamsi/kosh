// Package vault is Kosh's domain core. It ties together crypto (envelope key
// hierarchy), storage (encrypted SQLite) and audit (tamper-evident log) into a locked
// or unlocked vault that performs secret CRUD without ever persisting plaintext
// secrets or the master password.
package vault

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"kosh/internal/audit"
	"kosh/internal/crypto"
	"kosh/internal/storage"
)

var (
	// ErrLocked is returned when an operation requires an unlocked vault.
	ErrLocked = errors.New("vault: locked")
	// ErrAlreadyInitialized is returned by Init when a vault already exists.
	ErrAlreadyInitialized = errors.New("vault: already initialized")
	// ErrNotInitialized is returned by Unlock when no vault exists yet.
	ErrNotInitialized = errors.New("vault: not initialized")
	// ErrWrongPassword is returned when the master password fails verification.
	ErrWrongPassword = errors.New("vault: wrong password")
	// ErrNotFound is returned when a secret alias does not exist.
	ErrNotFound = errors.New("vault: secret not found")
)

// Environment enumerates the supported deployment environments.
type Environment string

const (
	Dev     Environment = "dev"
	QA      Environment = "qa"
	Staging Environment = "staging"
	Prod    Environment = "prod"
)

// ItemType classifies what a vault entry holds. The type is non-secret metadata; the
// sensitive payload always lives encrypted in value_enc (see internal/storage/migrations
// 0003). Existing entries and any zero value are treated as ItemAPIKey.
type ItemType string

const (
	ItemAPIKey     ItemType = "api_key"     // value_enc = raw key bytes
	ItemLogin      ItemType = "login"       // value_enc = JSON {"username","password"}
	ItemSecureNote ItemType = "secure_note" // value_enc = note text
	ItemKeyPair    ItemType = "keypair"     // value_enc = JSON {"accessKey","secretKey"}
)

// normalize maps the zero value to the default type so callers never have to.
func (t ItemType) normalize() ItemType {
	if t == "" {
		return ItemAPIKey
	}
	return t
}

func validItemType(t ItemType) bool {
	switch t {
	case ItemAPIKey, ItemLogin, ItemSecureNote, ItemKeyPair:
		return true
	}
	return false
}

// Secret is non-secret metadata about a stored credential. It never contains the
// plaintext value; use Reveal / RevealItem to obtain the payload on demand.
type Secret struct {
	ID           int64
	Alias        string
	ItemType     ItemType
	ProviderKey  string
	Environment  Environment
	Description  string
	CreatedAt    int64
	UpdatedAt    int64
	LastUsedAt   *int64
	ExpiresAt    *int64
	RotationDays *int
	Archived     bool
	IsFavorite   bool
	HasTOTP      bool
}

// Vault holds an opened database and, when unlocked, the in-memory DEK.
type Vault struct {
	db *storage.DB

	mu     sync.Mutex
	dek    []byte // nil when locked; zeroized on Lock
	hmac   []byte // vault-scoped subkey for duplicate-detection keyed hash
	actor  string // audit actor label for this session, e.g. "ui"
	autoAt time.Time
}

// Open opens the vault database at path (creating the file if absent). The vault is
// returned locked; call Init (first run) or Unlock.
func Open(path, actor string) (*Vault, error) {
	db, err := storage.Open(path)
	if err != nil {
		return nil, err
	}
	if actor == "" {
		actor = "ui"
	}
	return &Vault{db: db, actor: actor}, nil
}

// OpenDB creates a Vault over an already-opened *storage.DB. Useful in tests where a
// shared in-memory database is managed by the caller.
func OpenDB(db *storage.DB, actor string) (*Vault, error) {
	if actor == "" {
		actor = "ui"
	}
	return &Vault{db: db, actor: actor}, nil
}

// Close locks and closes the vault.
func (v *Vault) Close() error {
	v.Lock()
	return v.db.Close()
}

// DB returns the underlying storage.DB. Used by the desktop shell to run
// health, backup and audit queries directly.
func (v *Vault) DB() *storage.DB { return v.db }

// IsInitialized reports whether a vault_meta row exists.
func (v *Vault) IsInitialized() (bool, error) {
	var n int
	err := v.db.SQL().QueryRow(`SELECT count(*) FROM vault_meta WHERE id=1`).Scan(&n)
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// Unlocked reports whether the DEK is currently in memory.
func (v *Vault) Unlocked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.dek != nil
}

// Init creates a new vault protected by the master password. It generates a random
// DEK, wraps it under a KEK derived from the password, stores a verifier, and leaves
// the vault unlocked. Returns ErrAlreadyInitialized if a vault already exists.
func (v *Vault) Init(password []byte) error {
	init, err := v.IsInitialized()
	if err != nil {
		return err
	}
	if init {
		return ErrAlreadyInitialized
	}

	params := crypto.DefaultKDFParams()
	salt, err := crypto.NewSalt()
	if err != nil {
		return err
	}
	kek := crypto.DeriveKey(password, salt, params)
	defer crypto.Zero(kek)

	dek, err := crypto.NewKey()
	if err != nil {
		return err
	}
	wrapped, err := crypto.WrapKey(kek, dek)
	if err != nil {
		crypto.Zero(dek)
		return err
	}
	verifier, err := crypto.MakeVerifier(kek)
	if err != nil {
		crypto.Zero(dek)
		return err
	}

	ts := time.Now().Unix()

	tx, err := v.db.SQL().Begin()
	if err != nil {
		crypto.Zero(dek)
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(
		`INSERT INTO vault_meta(id,kdf,kdf_time,kdf_memory_kib,kdf_threads,kdf_salt,verifier,dek_wrapped,schema_version,created_at,updated_at)
		 VALUES(1,'argon2id',?,?,?,?,?,?,1,?,?)`,
		params.Time, params.MemoryKiB, params.Threads, salt, verifier, wrapped, ts, ts,
	); err != nil {
		crypto.Zero(dek)
		return fmt.Errorf("vault: write meta: %w", err)
	}
	if err = audit.LogTx(tx, v.actor, "init", "", audit.Allow, ""); err != nil {
		crypto.Zero(dek)
		return fmt.Errorf("vault: audit init: %w", err)
	}
	if err = tx.Commit(); err != nil {
		crypto.Zero(dek)
		return fmt.Errorf("vault: commit init: %w", err)
	}

	v.mu.Lock()
	v.dek = dek
	v.hmac = crypto.KeyedHash(dek, []byte("localvault/duplicate-subkey"))
	v.touch()
	v.mu.Unlock()
	return nil
}

// Unlock derives the KEK from the password, validates it against the stored verifier,
// unwraps the DEK into memory, and records an audit entry. Wrong passwords are audited
// as denied and never reveal whether the salt or verifier was the problem.
func (v *Vault) Unlock(password []byte) error {
	init, err := v.IsInitialized()
	if err != nil {
		return err
	}
	if !init {
		return ErrNotInitialized
	}

	// Throttle: if a previous burst of failures set a lockout window, refuse before
	// spending Argon2id — this both enforces the wait and avoids wasting CPU on an
	// attacker's guesses.
	if v.LockoutRemaining() > 0 {
		_ = audit.Log(v.db.SQL(), v.actor, "unlock", "", audit.Deny, "locked out")
		return ErrTooManyAttempts
	}

	var (
		p        crypto.KDFParams
		salt     []byte
		verifier []byte
		wrapped  []byte
	)
	row := v.db.SQL().QueryRow(`SELECT kdf_time,kdf_memory_kib,kdf_threads,kdf_salt,verifier,dek_wrapped FROM vault_meta WHERE id=1`)
	if err := row.Scan(&p.Time, &p.MemoryKiB, &p.Threads, &salt, &verifier, &wrapped); err != nil {
		return fmt.Errorf("vault: read meta: %w", err)
	}

	kek := crypto.DeriveKey(password, salt, p)
	defer crypto.Zero(kek)

	if !crypto.CheckVerifier(kek, verifier) {
		_ = audit.Log(v.db.SQL(), v.actor, "unlock", "", audit.Deny, "wrong password")
		v.recordUnlockFailure()
		return ErrWrongPassword
	}
	dek, err := crypto.UnwrapKey(kek, wrapped)
	if err != nil {
		_ = audit.Log(v.db.SQL(), v.actor, "unlock", "", audit.Deny, "unwrap failed")
		v.recordUnlockFailure()
		return ErrWrongPassword
	}

	v.mu.Lock()
	v.dek = dek
	v.hmac = crypto.KeyedHash(dek, []byte("localvault/duplicate-subkey"))
	v.touch()
	v.mu.Unlock()

	v.resetUnlockFailures()
	_ = audit.Log(v.db.SQL(), v.actor, "unlock", "", audit.Allow, "")
	return nil
}

// Lock zeroizes the in-memory DEK/subkey. Safe to call when already locked.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek != nil {
		crypto.Zero(v.dek)
		v.dek = nil
	}
	if v.hmac != nil {
		crypto.Zero(v.hmac)
		v.hmac = nil
	}
}

// AutoLockIfIdle locks the vault if more than d has elapsed since the last activity.
// Returns true if it locked. Callers (UI/CLI) invoke this on a timer.
func (v *Vault) AutoLockIfIdle(d time.Duration) bool {
	v.mu.Lock()
	idle := v.dek != nil && time.Since(v.autoAt) >= d
	v.mu.Unlock()
	if idle {
		v.Lock()
		_ = audit.Log(v.db.SQL(), v.actor, "autolock", "", audit.Allow, "")
		return true
	}
	return false
}

// touch updates the activity timestamp. Caller must hold v.mu.
func (v *Vault) touch() { v.autoAt = time.Now() }

// Touch records user activity so the idle auto-lock timer resets. The UI calls this
// (throttled) on interaction; it is a no-op when the vault is locked.
func (v *Vault) Touch() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek != nil {
		v.touch()
	}
}

// dekCopy returns a defensive copy of the DEK if unlocked, else ErrLocked.
func (v *Vault) dekCopy() ([]byte, []byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return nil, nil, ErrLocked
	}
	v.touch()
	dek := make([]byte, len(v.dek))
	copy(dek, v.dek)
	hm := make([]byte, len(v.hmac))
	copy(hm, v.hmac)
	return dek, hm, nil
}

func (v *Vault) providerID(key string) (int64, error) {
	var id int64
	err := v.db.SQL().QueryRow(`SELECT id FROM providers WHERE key=?`, key).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("vault: unknown provider %q", key)
	}
	return id, err
}

func (v *Vault) associatedData(id int64, providerKey string, env Environment) []byte {
	return []byte(fmt.Sprintf("%d|%s|%s", id, providerKey, env))
}
