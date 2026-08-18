// Package backup provides encrypted export and import of the Kosh database.
//
// A backup archive is a self-contained, authenticated binary blob:
//
//	Header (JSON, plaintext) || nonce || ciphertext || Poly1305 tag
//
// The header records the KDF parameters and salt used to derive the Backup Key (BK)
// from the master password, plus a format version. The entire vault contents
// (serialised as JSON) are encrypted with XChaCha20-Poly1305 under BK, with the
// header bytes bound as associated data. A forged or edited archive will fail the
// AEAD authentication check.
//
// The backup key is derived independently from the vault's DEK so that an attacker
// who obtains only a backup file still needs to break Argon2id to read anything.
//
// Portability: the archive carries the vault's own key material (the KEK salt, the
// verifier, and the DEK wrapped under the KEK) inside the encrypted body. That makes a
// backup a complete, self-contained vault: restoring it onto a brand-new install
// reproduces the original DEK, so the per-secret ciphertext decrypts with the SAME
// master password that was in use at export time. Without this the value_enc blobs
// would be undecryptable after a restore, because a fresh Init generates a new random
// DEK. The wrapped DEK is safe to include: it is encrypted under the KEK (Argon2id of
// the master password) and then again under the Backup Key.
package backup

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"kosh/internal/crypto"
)

// formatVersion 3 adds the per-secret item_type (api_key / login / secure_note). Version
// 2 added the vault_meta (key material) block so backups are restorable onto a fresh
// install; v2 archives are still accepted and their secrets restored as api_key. Version
// 1 archives (pre-portability alpha) held only ciphertext, cannot be restored to a new
// vault, and are rejected.
const formatVersion = 3

// ErrBadBackup is returned when a backup file cannot be authenticated or parsed.
var ErrBadBackup = errors.New("backup: invalid or corrupted backup")

// Header is the plaintext prefix of every backup archive. It contains only KDF
// parameters and non-secret metadata; no secrets are stored here.
type Header struct {
	FormatVersion int    `json:"v"`
	CreatedAt     int64  `json:"ts"`
	KDF           string `json:"kdf"`
	KDFTime       uint32 `json:"kdf_t"`
	KDFMemoryKiB  uint32 `json:"kdf_m"`
	KDFThreads    uint8  `json:"kdf_n"`
	Salt          []byte `json:"salt"`
}

// SecretRecord is the serialised representation of one secret inside a backup.
//
// ID is preserved and restored verbatim: each value_enc blob is sealed with the row id
// bound as associated data (see vault.associatedData), so a restore MUST reuse the
// original id or the AEAD authentication check fails and the value cannot be decrypted.
type SecretRecord struct {
	ID           int64  `json:"id"`
	Alias        string `json:"alias"`
	ItemType     string `json:"type,omitempty"` // empty in v2 archives → restored as api_key
	ProviderKey  string `json:"provider"`
	Environment  string `json:"env"`
	Description  string `json:"desc,omitempty"`
	ValueEnc     []byte `json:"venc"`
	ValueHash    []byte `json:"vhash"`
	CreatedAt    int64  `json:"cat"`
	UpdatedAt    int64  `json:"uat"`
	LastUsedAt   *int64 `json:"lua,omitempty"`
	ExpiresAt    *int64 `json:"exp,omitempty"`
	RotationDays *int   `json:"rot,omitempty"`
	FolderID     *int64 `json:"folder,omitempty"`
	CustomFields string `json:"custom,omitempty"`
	IsArchived   bool   `json:"arch,omitempty"`
}

// FolderRecord is one folder. ParentID is preserved so nested folder hierarchies survive
// a restore; the id is preserved so secrets and child folders that reference it stay
// consistent.
type FolderRecord struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	ParentID  *int64 `json:"parent,omitempty"`
	CreatedAt int64  `json:"cat"`
}

// TagRecord is one tag. The id is preserved so the secret↔tag associations restore
// against the correct rows.
type TagRecord struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// SecretTagRecord is one secret↔tag association (the secret_tags join table).
type SecretTagRecord struct {
	SecretID int64 `json:"s"`
	TagID    int64 `json:"t"`
}

// MetaRecord is the vault's key material (row id=1 of vault_meta), serialised into the
// snapshot so the backup is a self-contained, restorable vault. All of these fields are
// non-sensitive on their own: the salt and KDF cost are public parameters, the verifier
// only proves a password guess, and DEKWrapped is the DEK encrypted under the KEK. They
// live inside the AEAD-encrypted body regardless.
type MetaRecord struct {
	KDF           string `json:"kdf"`
	KDFTime       uint32 `json:"kdf_t"`
	KDFMemoryKiB  uint32 `json:"kdf_m"`
	KDFThreads    uint8  `json:"kdf_n"`
	Salt          []byte `json:"salt"`
	Verifier      []byte `json:"verifier"`
	DEKWrapped    []byte `json:"dek_wrapped"`
	SchemaVersion int    `json:"schema_version"`
	CreatedAt     int64  `json:"created_at"`
}

// VaultSnapshot is the complete vault contents serialised for backup: key material, the
// organisational structure (folders and tags), every secret with its custom fields and
// folder membership, and the secret↔tag associations. Secret values remain in their
// encrypted form (value_enc blobs) under the DEK described by Meta; the backup key
// authenticates the archive wrapper, not the per-secret encryption.
type VaultSnapshot struct {
	Meta       MetaRecord        `json:"meta"`
	Folders    []FolderRecord    `json:"folders,omitempty"`
	Tags       []TagRecord       `json:"tags,omitempty"`
	Secrets    []SecretRecord    `json:"secrets"`
	SecretTags []SecretTagRecord `json:"secret_tags,omitempty"`
}

// Export creates an encrypted backup blob from the current vault database. The
// masterPassword is used to derive a fresh Backup Key (BK); it is the same password
// the user uses to unlock the vault.
func Export(db *sql.DB, masterPassword []byte) ([]byte, error) {
	snap, err := snapshot(db)
	if err != nil {
		return nil, err
	}

	params := crypto.DefaultKDFParams()
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	bk := crypto.DeriveKey(masterPassword, salt, params)
	defer crypto.Zero(bk)

	hdr := Header{
		FormatVersion: formatVersion,
		CreatedAt:     time.Now().Unix(),
		KDF:           "argon2id",
		KDFTime:       params.Time,
		KDFMemoryKiB:  params.MemoryKiB,
		KDFThreads:    params.Threads,
		Salt:          salt,
	}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		return nil, fmt.Errorf("backup: marshal header: %w", err)
	}
	plaintext, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("backup: marshal snapshot: %w", err)
	}

	body, err := crypto.Encrypt(bk, plaintext, hdrBytes)
	if err != nil {
		return nil, err
	}

	// Archive = len(hdrBytes) as 4-byte big-endian || hdrBytes || body
	out := make([]byte, 4+len(hdrBytes)+len(body))
	out[0] = byte(len(hdrBytes) >> 24)
	out[1] = byte(len(hdrBytes) >> 16)
	out[2] = byte(len(hdrBytes) >> 8)
	out[3] = byte(len(hdrBytes))
	copy(out[4:], hdrBytes)
	copy(out[4+len(hdrBytes):], body)
	return out, nil
}

// Import decrypts and restores a backup archive into the vault database. It fully
// replaces the vault: the key material (vault_meta) and every secret are overwritten
// with the archive's contents, so after a successful Import the vault must be unlocked
// with the master password that was in effect when the backup was Exported. Any secret
// present in the current vault but absent from the backup is removed. masterPassword
// must match the password used when Export was called (the archive fails to
// authenticate otherwise).
func Import(db *sql.DB, archive, masterPassword []byte) error {
	if len(archive) < 4 {
		return ErrBadBackup
	}
	hdrLen := int(archive[0])<<24 | int(archive[1])<<16 | int(archive[2])<<8 | int(archive[3])
	if 4+hdrLen > len(archive) {
		return ErrBadBackup
	}
	hdrBytes := archive[4 : 4+hdrLen]
	body := archive[4+hdrLen:]

	var hdr Header
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return ErrBadBackup
	}
	if hdr.FormatVersion != formatVersion && hdr.FormatVersion != 2 {
		return fmt.Errorf("backup: unsupported format version %d", hdr.FormatVersion)
	}

	bk := crypto.DeriveKey(masterPassword, hdr.Salt, crypto.KDFParams{
		Time:      hdr.KDFTime,
		MemoryKiB: hdr.KDFMemoryKiB,
		Threads:   hdr.KDFThreads,
	})
	defer crypto.Zero(bk)

	plaintext, err := crypto.Decrypt(bk, body, hdrBytes)
	if err != nil {
		return ErrBadBackup
	}

	var snap VaultSnapshot
	if err := json.Unmarshal(plaintext, &snap); err != nil {
		return fmt.Errorf("backup: parse snapshot: %w", err)
	}

	return restore(db, snap)
}

// snapshot reads the vault key material, its folder/tag structure, and all secrets
// (ciphertext blobs, never plaintext) from db — archived secrets included, so a backup
// is a faithful, complete copy of the vault.
func snapshot(db *sql.DB) (VaultSnapshot, error) {
	var snap VaultSnapshot
	err := db.QueryRow(
		`SELECT kdf, kdf_time, kdf_memory_kib, kdf_threads, kdf_salt, verifier, dek_wrapped, schema_version, created_at
		   FROM vault_meta WHERE id=1`).Scan(
		&snap.Meta.KDF, &snap.Meta.KDFTime, &snap.Meta.KDFMemoryKiB, &snap.Meta.KDFThreads,
		&snap.Meta.Salt, &snap.Meta.Verifier, &snap.Meta.DEKWrapped,
		&snap.Meta.SchemaVersion, &snap.Meta.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return VaultSnapshot{}, fmt.Errorf("backup: vault not initialized")
	} else if err != nil {
		return VaultSnapshot{}, fmt.Errorf("backup: read vault_meta: %w", err)
	}

	// Folders, ordered by id so parents precede children (a parent is always created
	// before its child, hence has a lower id) — this makes the restore insert order
	// satisfy the self-referential foreign key without deferral.
	frows, err := db.Query(`SELECT id, name, parent_id, created_at FROM folders ORDER BY id`)
	if err != nil {
		return VaultSnapshot{}, fmt.Errorf("backup: folders query: %w", err)
	}
	for frows.Next() {
		var f FolderRecord
		if err := frows.Scan(&f.ID, &f.Name, &f.ParentID, &f.CreatedAt); err != nil {
			frows.Close()
			return VaultSnapshot{}, err
		}
		snap.Folders = append(snap.Folders, f)
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return VaultSnapshot{}, err
	}

	// Tags.
	trows, err := db.Query(`SELECT id, name FROM tags ORDER BY id`)
	if err != nil {
		return VaultSnapshot{}, fmt.Errorf("backup: tags query: %w", err)
	}
	for trows.Next() {
		var tg TagRecord
		if err := trows.Scan(&tg.ID, &tg.Name); err != nil {
			trows.Close()
			return VaultSnapshot{}, err
		}
		snap.Tags = append(snap.Tags, tg)
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return VaultSnapshot{}, err
	}

	// All secrets (archived included), with folder membership and custom fields.
	rows, err := db.Query(
		`SELECT s.id, s.alias, COALESCE(s.item_type,'api_key'), p.key, s.environment,
		        COALESCE(s.description,''), s.value_enc, s.value_hash,
		        s.created_at, s.updated_at, s.last_used_at, s.expires_at, s.rotation_days,
		        s.folder_id, COALESCE(s.custom_fields,'{}'), s.is_archived
		   FROM secrets s JOIN providers p ON p.id=s.provider_id`)
	if err != nil {
		return VaultSnapshot{}, fmt.Errorf("backup: snapshot query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var r SecretRecord
		var archived int
		if err := rows.Scan(
			&r.ID, &r.Alias, &r.ItemType, &r.ProviderKey, &r.Environment, &r.Description,
			&r.ValueEnc, &r.ValueHash, &r.CreatedAt, &r.UpdatedAt,
			&r.LastUsedAt, &r.ExpiresAt, &r.RotationDays,
			&r.FolderID, &r.CustomFields, &archived,
		); err != nil {
			return VaultSnapshot{}, err
		}
		r.IsArchived = archived == 1
		snap.Secrets = append(snap.Secrets, r)
	}
	if err := rows.Err(); err != nil {
		return VaultSnapshot{}, err
	}

	// Every secret↔tag association (all secrets are captured, so no filter is needed).
	strows, err := db.Query(`SELECT secret_id, tag_id FROM secret_tags`)
	if err != nil {
		return VaultSnapshot{}, fmt.Errorf("backup: secret_tags query: %w", err)
	}
	defer strows.Close()
	for strows.Next() {
		var st SecretTagRecord
		if err := strows.Scan(&st.SecretID, &st.TagID); err != nil {
			return VaultSnapshot{}, err
		}
		snap.SecretTags = append(snap.SecretTags, st)
	}
	return snap, strows.Err()
}

// restore replaces the vault's key material and secrets with the snapshot's contents in
// a single transaction. It writes vault_meta (so the original DEK is reproduced and the
// ciphertext decrypts under the export-time password) and clears any secrets not present
// in the backup, making the restore a faithful full-vault replacement rather than a
// merge.
func restore(db *sql.DB, snap VaultSnapshot) error {
	if len(snap.Meta.DEKWrapped) == 0 || len(snap.Meta.Salt) == 0 {
		return fmt.Errorf("backup: snapshot missing key material")
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Overwrite the vault key material so the restored ciphertext is decryptable with the
	// password used at export time.
	if _, err := tx.Exec(
		`INSERT INTO vault_meta(id,kdf,kdf_time,kdf_memory_kib,kdf_threads,kdf_salt,verifier,dek_wrapped,schema_version,created_at,updated_at)
		 VALUES(1,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET
		   kdf=excluded.kdf, kdf_time=excluded.kdf_time, kdf_memory_kib=excluded.kdf_memory_kib,
		   kdf_threads=excluded.kdf_threads, kdf_salt=excluded.kdf_salt, verifier=excluded.verifier,
		   dek_wrapped=excluded.dek_wrapped, schema_version=excluded.schema_version, updated_at=excluded.updated_at`,
		snap.Meta.KDF, snap.Meta.KDFTime, snap.Meta.KDFMemoryKiB, snap.Meta.KDFThreads,
		snap.Meta.Salt, snap.Meta.Verifier, snap.Meta.DEKWrapped, snap.Meta.SchemaVersion,
		snap.Meta.CreatedAt, time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("backup: restore vault_meta: %w", err)
	}

	// Replace all organisational state and secrets wholesale so the restore mirrors the
	// archive exactly. Clear children before parents to respect foreign keys.
	for _, stmt := range []string{
		`DELETE FROM secret_tags`,
		`DELETE FROM secrets`,
		`DELETE FROM folders`,
		`DELETE FROM tags`,
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("backup: clear (%s): %w", stmt, err)
		}
	}

	// Folders first (parents before children — the snapshot is ordered by id) so that
	// both child folders and secrets can reference them.
	for _, f := range snap.Folders {
		if _, err := tx.Exec(
			`INSERT INTO folders(id,name,parent_id,created_at) VALUES(?,?,?,?)`,
			f.ID, f.Name, f.ParentID, f.CreatedAt,
		); err != nil {
			return fmt.Errorf("backup: restore folder %q: %w", f.Name, err)
		}
	}

	// Tags (independent of secrets).
	for _, tg := range snap.Tags {
		if _, err := tx.Exec(
			`INSERT INTO tags(id,name) VALUES(?,?)`, tg.ID, tg.Name,
		); err != nil {
			return fmt.Errorf("backup: restore tag %q: %w", tg.Name, err)
		}
	}

	for _, r := range snap.Secrets {
		var providerID int64
		err := tx.QueryRow(`SELECT id FROM providers WHERE key=?`, r.ProviderKey).Scan(&providerID)
		if err == sql.ErrNoRows {
			_, err = tx.Exec(`INSERT OR IGNORE INTO providers(key,name,category,is_builtin,created_at) VALUES(?,?,?,0,?)`,
				r.ProviderKey, r.ProviderKey, "custom", time.Now().Unix())
			if err != nil {
				return err
			}
			tx.QueryRow(`SELECT id FROM providers WHERE key=?`, r.ProviderKey).Scan(&providerID)
		} else if err != nil {
			return err
		}

		customFields := r.CustomFields
		if customFields == "" {
			customFields = "{}"
		}

		archived := 0
		if r.IsArchived {
			archived = 1
		}

		itemType := r.ItemType
		if itemType == "" {
			itemType = "api_key" // v2 archives predate item types
		}

		// Insert with the original id so the value_enc AAD (which binds the row id)
		// still authenticates on Reveal.
		_, err = tx.Exec(
			`INSERT INTO secrets
			 (id,alias,item_type,provider_id,environment,description,value_enc,value_hash,
			  created_at,updated_at,last_used_at,expires_at,rotation_days,folder_id,custom_fields,is_archived)
			 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			r.ID, r.Alias, itemType, providerID, r.Environment, r.Description,
			r.ValueEnc, r.ValueHash,
			r.CreatedAt, r.UpdatedAt, r.LastUsedAt, r.ExpiresAt, r.RotationDays,
			r.FolderID, customFields, archived,
		)
		if err != nil {
			return fmt.Errorf("backup: restore %s: %w", r.Alias, err)
		}
	}

	// Finally the secret↔tag associations, now that both sides exist.
	for _, st := range snap.SecretTags {
		if _, err := tx.Exec(
			`INSERT INTO secret_tags(secret_id,tag_id) VALUES(?,?)`, st.SecretID, st.TagID,
		); err != nil {
			return fmt.Errorf("backup: restore secret_tag (%d,%d): %w", st.SecretID, st.TagID, err)
		}
	}

	return tx.Commit()
}
