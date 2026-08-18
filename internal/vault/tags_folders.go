package vault

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"kosh/internal/audit"
)

// Folder is a lightweight folder for organising secrets.
type Folder struct {
	ID       int64
	Name     string
	ParentID *int64
}

// Tag is a label that can be attached to multiple secrets.
type Tag struct {
	ID   int64
	Name string
}

// SecretSummary is the alias + key metadata returned by ListNames. It never contains
// a secret value; it is intentionally cheap to produce (no decryption).
type SecretSummary struct {
	ID           int64
	Alias        string
	ItemType     ItemType
	ProviderKey  string
	ProviderName string
	Environment  Environment
	Tags         []string
	FolderName   string
	Description  string
	ExpiresAt    *int64
	LastUsedAt   *int64
	IsArchived   bool
	CustomFields string
}

// ListNames returns all SecretSummaries for the unlocked vault, newest first.
// This is the "what passwords do I have?" query: names and metadata only, no decryption.
func (v *Vault) ListNames(filter ListFilter) ([]SecretSummary, error) {
	if !v.Unlocked() {
		return nil, ErrLocked
	}

	q := `SELECT s.id, s.alias, s.item_type, p.key, p.name,
	             s.environment, COALESCE(s.description,''),
	             s.expires_at, s.last_used_at, s.is_archived,
	             COALESCE(f.name,''), COALESCE(s.custom_fields,'{}')
	        FROM secrets s
	        JOIN providers p ON p.id=s.provider_id
	        LEFT JOIN folders f ON f.id=s.folder_id
	        WHERE 1=1`
	var args []any

	if filter.ProviderKey != "" {
		q += " AND p.key=?"
		args = append(args, filter.ProviderKey)
	}
	if filter.Environment != "" {
		q += " AND s.environment=?"
		args = append(args, string(filter.Environment))
	}
	if !filter.IncludeArchived {
		q += " AND s.is_archived=0"
	}
	if filter.Search != "" {
		q += " AND (s.alias LIKE ? OR COALESCE(s.description,'') LIKE ?)"
		pat := "%" + filter.Search + "%"
		args = append(args, pat, pat)
	}
	q += " ORDER BY s.created_at DESC"

	rows, err := v.db.SQL().Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("vault: list names: %w", err)
	}
	defer rows.Close()

	var out []SecretSummary
	for rows.Next() {
		var s SecretSummary
		var env, itemType string
		var archived int
		var folderName string
		if err := rows.Scan(&s.ID, &s.Alias, &itemType, &s.ProviderKey, &s.ProviderName,
			&env, &s.Description, &s.ExpiresAt, &s.LastUsedAt, &archived, &folderName, &s.CustomFields); err != nil {
			return nil, err
		}
		s.ItemType = ItemType(itemType).normalize()
		s.Environment = Environment(env)
		s.IsArchived = archived == 1
		s.FolderName = folderName
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	for i := range out {
		out[i].Tags = loadTags(v.db.SQL(), out[i].ID)
	}
	return out, nil
}

// ListFilter narrows the results of ListNames.
type ListFilter struct {
	ProviderKey     string
	Environment     Environment
	Search          string
	IncludeArchived bool
}

func loadTags(db *sql.DB, secretID int64) []string {
	rows, err := db.Query(
		`SELECT t.name FROM tags t JOIN secret_tags st ON st.tag_id=t.id WHERE st.secret_id=?`,
		secretID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			tags = append(tags, n)
		}
	}
	return tags
}

// AddFolder creates a folder, optionally nested under parentID.
func (v *Vault) AddFolder(name string, parentID *int64) (int64, error) {
	if !v.Unlocked() {
		return 0, ErrLocked
	}
	res, err := v.db.SQL().Exec(
		`INSERT INTO folders(name,parent_id,created_at) VALUES(?,?,?)`,
		name, parentID, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("vault: add folder: %w", err)
	}
	return res.LastInsertId()
}

// ListFolders returns all folders.
func (v *Vault) ListFolders() ([]Folder, error) {
	if !v.Unlocked() {
		return nil, ErrLocked
	}
	rows, err := v.db.SQL().Query(`SELECT id,name,parent_id FROM folders ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Folder
	for rows.Next() {
		var f Folder
		if err := rows.Scan(&f.ID, &f.Name, &f.ParentID); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// AddTag creates a tag (idempotent).
func (v *Vault) AddTag(name string) (int64, error) {
	if !v.Unlocked() {
		return 0, ErrLocked
	}
	_, _ = v.db.SQL().Exec(`INSERT OR IGNORE INTO tags(name) VALUES(?)`, name)
	var id int64
	err := v.db.SQL().QueryRow(`SELECT id FROM tags WHERE name=?`, name).Scan(&id)
	return id, err
}

// TagSecret attaches a tag (by name) to a secret (by alias).
func (v *Vault) TagSecret(alias, tagName string) error {
	if !v.Unlocked() {
		return ErrLocked
	}
	tagID, err := v.AddTag(tagName)
	if err != nil {
		return err
	}
	var secretID int64
	if err := v.db.SQL().QueryRow(`SELECT id FROM secrets WHERE alias=?`, alias).Scan(&secretID); err == sql.ErrNoRows {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	_, err = v.db.SQL().Exec(
		`INSERT OR IGNORE INTO secret_tags(secret_id,tag_id) VALUES(?,?)`, secretID, tagID)
	return err
}

// ListTags returns all distinct tags.
func (v *Vault) ListTags() ([]Tag, error) {
	if !v.Unlocked() {
		return nil, ErrLocked
	}
	rows, err := v.db.SQL().Query(`SELECT id,name FROM tags ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Tag
	for rows.Next() {
		var t Tag
		if err := rows.Scan(&t.ID, &t.Name); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// MoveToFolder sets the folder_id for a secret.
func (v *Vault) MoveToFolder(alias string, folderID *int64) error {
	if !v.Unlocked() {
		return ErrLocked
	}
	tx, err := v.db.SQL().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE secrets SET folder_id=? WHERE alias=?`, folderID, alias)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	if err := audit.LogTx(tx, v.actor, "move_folder", alias, audit.Allow, ""); err != nil {
		return fmt.Errorf("vault: audit move_folder: %w", err)
	}
	return tx.Commit()
}

// ArchiveSecret marks a secret as archived (it stays in the vault but is excluded
// from default listing and health scoring).
func (v *Vault) ArchiveSecret(alias string, archived bool) error {
	if !v.Unlocked() {
		return ErrLocked
	}
	val := 0
	if archived {
		val = 1
	}
	tx, err := v.db.SQL().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE secrets SET is_archived=? WHERE alias=?`, val, alias)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	action := "archive"
	if !archived {
		action = "unarchive"
	}
	if err := audit.LogTx(tx, v.actor, action, alias, audit.Allow, ""); err != nil {
		return fmt.Errorf("vault: audit %s: %w", action, err)
	}
	return tx.Commit()
}

// GetCustomFields returns the raw JSON string of custom fields for a secret by alias.
func (v *Vault) GetCustomFields(alias string) (string, error) {
	if !v.Unlocked() {
		return "", ErrLocked
	}
	var cf string
	err := v.db.SQL().QueryRow(
		`SELECT COALESCE(custom_fields,'{}') FROM secrets WHERE alias=?`, alias).Scan(&cf)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return cf, err
}

// SetCustomFields stores a JSON string of custom fields for a secret by alias.
// The value must be valid JSON (the vault does not enforce a schema). An empty string is
// treated as an empty object; anything that is not valid JSON is rejected so malformed
// data can never be persisted.
func (v *Vault) SetCustomFields(alias, jsonFields string) error {
	if !v.Unlocked() {
		return ErrLocked
	}
	if jsonFields == "" {
		jsonFields = "{}"
	}
	if !json.Valid([]byte(jsonFields)) {
		return fmt.Errorf("vault: custom fields must be valid JSON")
	}
	tx, err := v.db.SQL().Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(
		`UPDATE secrets SET custom_fields=?, updated_at=? WHERE alias=?`,
		jsonFields, time.Now().Unix(), alias)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	if err := audit.LogTx(tx, v.actor, "set_custom_fields", alias, audit.Allow, ""); err != nil {
		return fmt.Errorf("vault: audit set_custom_fields: %w", err)
	}
	return tx.Commit()
}
