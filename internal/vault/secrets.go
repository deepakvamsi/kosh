package vault

import (
	"database/sql"
	"fmt"
	"time"

	"kosh/internal/audit"
	"kosh/internal/crypto"
)

// AddSecretInput describes a new vault entry to store. The fields used depend on
// ItemType (see encodeItemPayload): ItemAPIKey uses Value; ItemLogin uses Username +
// Password; ItemSecureNote uses Note. All secret material is encrypted immediately and
// never persisted in clear.
type AddSecretInput struct {
	Alias        string
	ItemType     ItemType // "" is treated as ItemAPIKey
	ProviderKey  string
	Environment  Environment
	Description  string
	Value        []byte // ItemAPIKey: the raw key/token
	Username     string // ItemLogin: account identifier (encrypted with the payload)
	Password     string // ItemLogin: the password
	Note         string // ItemSecureNote: free-form note body
	AccessKey    string // ItemKeyPair: the access key (e.g. AWS access key id)
	SecretKey    string // ItemKeyPair: the secret key
	TOTP         string // optional base32 TOTP seed (encrypted separately)
	ExpiresAt    *int64
	RotationDays *int
}

// AddSecret encrypts and stores a new entry. The type-specific plaintext payload is
// encrypted under the DEK with provider/environment bound as associated data, and a
// keyed hash is stored for duplicate detection. Plaintext buffers are zeroized.
func (v *Vault) AddSecret(in AddSecretInput) (int64, error) {
	dek, hm, err := v.dekCopy()
	if err != nil {
		return 0, err
	}
	defer crypto.Zero(dek)
	defer crypto.Zero(hm)
	defer crypto.Zero(in.Value)

	in.ItemType = in.ItemType.normalize()
	if !validItemType(in.ItemType) {
		return 0, fmt.Errorf("vault: invalid item type %q", in.ItemType)
	}

	pid, err := v.providerID(in.ProviderKey)
	if err != nil {
		return 0, err
	}
	if !validEnv(in.Environment) {
		return 0, fmt.Errorf("vault: invalid environment %q", in.Environment)
	}

	// Build the canonical plaintext for this item type and zeroize it afterwards. For
	// ItemAPIKey this aliases in.Value (already zeroized above); double-zero is harmless.
	pt, err := encodeItemPayload(in)
	if err != nil {
		return 0, err
	}
	defer crypto.Zero(pt)

	valueHash := crypto.KeyedHash(hm, pt)

	ts := time.Now().Unix()

	// The whole insert runs in one transaction so a crash or failure can never leave a
	// row with an empty (undecryptable) value_enc behind. We insert a placeholder blob
	// first to obtain the row id, then encrypt binding that id as associated data and
	// update — this binds the ciphertext to its own row — and record the audit entry in
	// the same transaction so the tamper-evident log can never drift from the data.
	tx, err := v.db.SQL().Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`INSERT INTO secrets(alias,item_type,provider_id,environment,description,value_enc,value_hash,created_at,updated_at,expires_at,rotation_days)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		in.Alias, string(in.ItemType), pid, string(in.Environment), in.Description, []byte{}, valueHash, ts, ts, in.ExpiresAt, in.RotationDays,
	)
	if err != nil {
		return 0, fmt.Errorf("vault: insert secret: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	ad := v.associatedData(id, in.ProviderKey, in.Environment)
	blob, err := crypto.Encrypt(dek, pt, ad)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE secrets SET value_enc=? WHERE id=?`, blob, id); err != nil {
		return 0, fmt.Errorf("vault: store ciphertext: %w", err)
	}
	if in.TOTP != "" {
		totpBlob, terr := v.encryptTOTP(dek, id, in.ProviderKey, in.Environment, in.TOTP)
		if terr != nil {
			return 0, terr
		}
		if _, err := tx.Exec(`UPDATE secrets SET totp_enc=? WHERE id=?`, totpBlob, id); err != nil {
			return 0, fmt.Errorf("vault: store totp: %w", err)
		}
	}
	if err := audit.LogTx(tx, v.actor, "create", in.Alias, audit.Allow, ""); err != nil {
		return 0, fmt.Errorf("vault: audit create: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("vault: commit secret: %w", err)
	}
	return id, nil
}

// Reveal decrypts and returns the raw stored plaintext for an alias, updating
// last_used_at and writing an audit record. For a login the raw bytes are the
// {"username","password"} JSON and for a secure note the note body; use RevealItem for a
// decoded, type-aware result. The caller must zeroize the returned slice promptly.
func (v *Vault) Reveal(alias string) ([]byte, error) {
	_, pt, err := v.revealRaw(alias)
	return pt, err
}

// revealRaw decrypts the payload for alias, records the audit reveal and bumps
// last_used_at in one transaction, and returns the entry's item type alongside the
// plaintext. Auditability is a hard requirement: if the reveal cannot be recorded, the
// plaintext is zeroized and an error returned rather than handed back unlogged.
func (v *Vault) revealRaw(alias string) (ItemType, []byte, error) {
	dek, _, err := v.dekCopy()
	if err != nil {
		return "", nil, err
	}
	defer crypto.Zero(dek)

	var (
		id          int64
		providerKey string
		env         string
		itemType    string
		blob        []byte
	)
	row := v.db.SQL().QueryRow(
		`SELECT s.id, p.key, s.environment, s.item_type, s.value_enc
		   FROM secrets s JOIN providers p ON p.id=s.provider_id
		  WHERE s.alias=?`, alias)
	if err := row.Scan(&id, &providerKey, &env, &itemType, &blob); err == sql.ErrNoRows {
		return "", nil, ErrNotFound
	} else if err != nil {
		return "", nil, err
	}

	ad := v.associatedData(id, providerKey, Environment(env))
	pt, err := crypto.Decrypt(dek, blob, ad)
	if err != nil {
		_ = audit.Log(v.db.SQL(), v.actor, "reveal", alias, audit.Deny, "decrypt failed")
		return "", nil, err
	}

	tx, err := v.db.SQL().Begin()
	if err != nil {
		crypto.Zero(pt)
		return "", nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE secrets SET last_used_at=? WHERE id=?`, time.Now().Unix(), id); err != nil {
		crypto.Zero(pt)
		return "", nil, err
	}
	if err := audit.LogTx(tx, v.actor, "reveal", alias, audit.Allow, ""); err != nil {
		crypto.Zero(pt)
		return "", nil, fmt.Errorf("vault: audit reveal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		crypto.Zero(pt)
		return "", nil, err
	}
	return ItemType(itemType).normalize(), pt, nil
}

// UpdateValue replaces the stored value for an alias. The old duplicate hash is
// recomputed. Plaintext is zeroized after use.
func (v *Vault) UpdateValue(alias string, newValue []byte) error {
	dek, hm, err := v.dekCopy()
	if err != nil {
		return err
	}
	defer crypto.Zero(dek)
	defer crypto.Zero(hm)
	defer crypto.Zero(newValue)

	var (
		id          int64
		providerKey string
		env         string
	)
	row := v.db.SQL().QueryRow(
		`SELECT s.id, p.key, s.environment FROM secrets s JOIN providers p ON p.id=s.provider_id WHERE s.alias=?`, alias)
	if err := row.Scan(&id, &providerKey, &env); err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}

	ad := v.associatedData(id, providerKey, Environment(env))
	blob, err := crypto.Encrypt(dek, newValue, ad)
	if err != nil {
		return err
	}
	valueHash := crypto.KeyedHash(hm, newValue)

	ts := time.Now().Unix()
	tx, err := v.db.SQL().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE secrets SET value_enc=?, value_hash=?, updated_at=? WHERE id=?`,
		blob, valueHash, ts, id); err != nil {
		return err
	}
	if err := audit.LogTx(tx, v.actor, "update", alias, audit.Allow, ""); err != nil {
		return fmt.Errorf("vault: audit update: %w", err)
	}
	return tx.Commit()
}

// DeleteSecret removes a secret by alias.
func (v *Vault) DeleteSecret(alias string) error {
	if !v.Unlocked() {
		return ErrLocked
	}
	tx, err := v.db.SQL().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM secrets WHERE alias=?`, alias)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	if err := audit.LogTx(tx, v.actor, "delete", alias, audit.Allow, ""); err != nil {
		return fmt.Errorf("vault: audit delete: %w", err)
	}
	return tx.Commit()
}

// ListSecrets returns metadata for all secrets (no values), newest first.
func (v *Vault) ListSecrets() ([]Secret, error) {
	if !v.Unlocked() {
		return nil, ErrLocked
	}
	rows, err := v.db.SQL().Query(
		`SELECT s.id,s.alias,s.item_type,p.key,s.environment,COALESCE(s.description,''),s.created_at,s.updated_at,
		        s.last_used_at,s.expires_at,s.rotation_days,s.is_archived
		   FROM secrets s JOIN providers p ON p.id=s.provider_id
		  ORDER BY s.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Secret
	for rows.Next() {
		var s Secret
		var env, itemType string
		var archived int
		if err := rows.Scan(&s.ID, &s.Alias, &itemType, &s.ProviderKey, &env, &s.Description,
			&s.CreatedAt, &s.UpdatedAt, &s.LastUsedAt, &s.ExpiresAt, &s.RotationDays, &archived); err != nil {
			return nil, err
		}
		s.ItemType = ItemType(itemType).normalize()
		s.Environment = Environment(env)
		s.Archived = archived == 1
		out = append(out, s)
	}
	return out, rows.Err()
}

func validEnv(e Environment) bool {
	switch e {
	case Dev, QA, Staging, Prod:
		return true
	}
	return false
}
