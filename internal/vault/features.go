package vault

import (
	"database/sql"
	"fmt"
	"time"

	"kosh/internal/audit"
	"kosh/internal/crypto"
	"kosh/internal/totp"
)

// ---------- Favorites ----------

// SetFavorite pins (fav=true) or unpins a secret. Favorites sort to the top of the list.
func (v *Vault) SetFavorite(alias string, fav bool) error {
	if !v.Unlocked() {
		return ErrLocked
	}
	val := 0
	if fav {
		val = 1
	}
	res, err := v.db.SQL().Exec(`UPDATE secrets SET is_favorite=? WHERE alias=?`, val, alias)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- TOTP (2FA) ----------

// totpAAD binds the encrypted TOTP seed to its row with a distinct domain tag, so a seed
// blob can never be swapped with the row's value_enc.
func (v *Vault) totpAAD(id int64, providerKey string, env Environment) []byte {
	return append(v.associatedData(id, providerKey, env), []byte("|totp")...)
}

func (v *Vault) encryptTOTP(dek []byte, id int64, providerKey string, env Environment, seed string) ([]byte, error) {
	norm := totp.Normalize(seed)
	if err := totp.Validate(norm); err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	return crypto.Encrypt(dek, []byte(norm), v.totpAAD(id, providerKey, env))
}

// SetTOTP sets, or (with an empty/whitespace seed) removes, the TOTP seed for an alias.
func (v *Vault) SetTOTP(alias, seed string) error {
	dek, _, err := v.dekCopy()
	if err != nil {
		return err
	}
	defer crypto.Zero(dek)

	id, providerKey, env, err := v.secretRowKey(alias)
	if err != nil {
		return err
	}

	if totp.Normalize(seed) == "" {
		if _, err := v.db.SQL().Exec(`UPDATE secrets SET totp_enc=NULL WHERE id=?`, id); err != nil {
			return err
		}
		_ = audit.Log(v.db.SQL(), v.actor, "totp_remove", alias, audit.Allow, "")
		return nil
	}

	blob, err := v.encryptTOTP(dek, id, providerKey, env, seed)
	if err != nil {
		return err
	}
	if _, err := v.db.SQL().Exec(`UPDATE secrets SET totp_enc=? WHERE id=?`, blob, id); err != nil {
		return err
	}
	_ = audit.Log(v.db.SQL(), v.actor, "totp_set", alias, audit.Allow, "")
	return nil
}

// TOTPCode returns the current 6-digit code and seconds remaining for an alias that has a
// TOTP seed. It is deliberately NOT audited per call: the code is a rotating derived value
// the UI polls once a second — configuring the seed is what gets logged, not each tick.
func (v *Vault) TOTPCode(alias string) (code string, remaining int, err error) {
	dek, _, err := v.dekCopy()
	if err != nil {
		return "", 0, err
	}
	defer crypto.Zero(dek)

	var (
		id          int64
		providerKey string
		env         string
		blob        []byte
	)
	row := v.db.SQL().QueryRow(
		`SELECT s.id, p.key, s.environment, s.totp_enc FROM secrets s JOIN providers p ON p.id=s.provider_id WHERE s.alias=?`, alias)
	if err := row.Scan(&id, &providerKey, &env, &blob); err == sql.ErrNoRows {
		return "", 0, ErrNotFound
	} else if err != nil {
		return "", 0, err
	}
	if len(blob) == 0 {
		return "", 0, ErrNotFound
	}
	seed, err := crypto.Decrypt(dek, blob, v.totpAAD(id, providerKey, Environment(env)))
	if err != nil {
		return "", 0, err
	}
	defer crypto.Zero(seed)
	return totp.Code(string(seed), time.Now())
}

// ---------- Password history ----------

// HistoryEntry is metadata about a retained previous value (never the plaintext).
type HistoryEntry struct {
	ID        int64
	ChangedAt int64
}

// ListHistory returns retained previous-value entries for an alias, newest first.
func (v *Vault) ListHistory(alias string) ([]HistoryEntry, error) {
	if !v.Unlocked() {
		return nil, ErrLocked
	}
	rows, err := v.db.SQL().Query(
		`SELECT h.id, h.changed_at FROM secret_history h
		   JOIN secrets s ON s.id=h.secret_id WHERE s.alias=? ORDER BY h.changed_at DESC`, alias)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		if err := rows.Scan(&e.ID, &e.ChangedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RevealHistoryValue decrypts a previous value by history id. The retained ciphertext was
// bound to the same row (id|provider|env), so it decrypts under the current DEK. Audited.
func (v *Vault) RevealHistoryValue(alias string, historyID int64) (string, error) {
	dek, _, err := v.dekCopy()
	if err != nil {
		return "", err
	}
	defer crypto.Zero(dek)

	var (
		id          int64
		providerKey string
		env         string
		blob        []byte
	)
	row := v.db.SQL().QueryRow(
		`SELECT s.id, p.key, s.environment, h.value_enc
		   FROM secret_history h JOIN secrets s ON s.id=h.secret_id
		  WHERE h.id=? AND s.alias=?`, historyID, alias)
	if err := row.Scan(&id, &providerKey, &env, &blob); err == sql.ErrNoRows {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	pt, err := crypto.Decrypt(dek, blob, v.associatedData(id, providerKey, Environment(env)))
	if err != nil {
		return "", err
	}
	defer crypto.Zero(pt)
	_ = audit.Log(v.db.SQL(), v.actor, "reveal_history", alias, audit.Allow, "")
	return string(pt), nil
}

// secretRowKey fetches the identity fields needed to build associated data for an alias.
func (v *Vault) secretRowKey(alias string) (id int64, providerKey string, env Environment, err error) {
	var e string
	row := v.db.SQL().QueryRow(
		`SELECT s.id, p.key, s.environment FROM secrets s JOIN providers p ON p.id=s.provider_id WHERE s.alias=?`, alias)
	switch scanErr := row.Scan(&id, &providerKey, &e); scanErr {
	case sql.ErrNoRows:
		return 0, "", "", ErrNotFound
	case nil:
		return id, providerKey, Environment(e), nil
	default:
		return 0, "", "", scanErr
	}
}
