package vault

import (
	"encoding/json"
	"fmt"
	"strings"

	"kosh/internal/crypto"
)

// loginPayload is the canonical, versioned plaintext shape stored (encrypted) in
// value_enc for ItemLogin entries. It is marshaled to JSON, encrypted under the DEK, and
// never written to any plaintext column — so the username is protected exactly like the
// password.
type loginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// encodeItemPayload produces the plaintext bytes to encrypt for a given input, enforcing
// type-aware validation in the core (not the UI). For ItemAPIKey it returns in.Value
// directly (backward compatible with pre-item-type vaults); other types are encoded so
// their sensitive fields live only inside value_enc.
func encodeItemPayload(in AddSecretInput) ([]byte, error) {
	switch in.ItemType.normalize() {
	case ItemAPIKey:
		if len(in.Value) == 0 {
			return nil, fmt.Errorf("vault: api_key requires a non-empty value")
		}
		return in.Value, nil

	case ItemLogin:
		if strings.TrimSpace(in.Username) == "" {
			return nil, fmt.Errorf("vault: login requires a username")
		}
		if in.Password == "" {
			return nil, fmt.Errorf("vault: login requires a password")
		}
		b, err := json.Marshal(loginPayload{Username: in.Username, Password: in.Password})
		if err != nil {
			return nil, fmt.Errorf("vault: encode login: %w", err)
		}
		return b, nil

	case ItemSecureNote:
		if in.Note == "" {
			return nil, fmt.Errorf("vault: secure_note requires a body")
		}
		return []byte(in.Note), nil

	default:
		return nil, fmt.Errorf("vault: invalid item type %q", in.ItemType)
	}
}

// RevealedItem is the decoded, type-aware result of revealing an entry. Only the fields
// relevant to ItemType are populated. Callers should treat every string field as
// sensitive and drop references as soon as possible.
type RevealedItem struct {
	ItemType ItemType
	Value    string // ItemAPIKey: the raw key/token
	Username string // ItemLogin
	Password string // ItemLogin
	Note     string // ItemSecureNote
}

// RevealItem decrypts an entry and returns it decoded per its stored item type, recording
// the same single audited reveal as Reveal. A login whose stored payload predates the
// JSON encoding (or is otherwise unparseable) is surfaced as its raw text in Value so no
// data is ever lost.
func (v *Vault) RevealItem(alias string) (RevealedItem, error) {
	itemType, pt, err := v.revealRaw(alias)
	if err != nil {
		return RevealedItem{}, err
	}
	defer crypto.Zero(pt)

	out := RevealedItem{ItemType: itemType}
	switch itemType {
	case ItemLogin:
		var lp loginPayload
		if err := json.Unmarshal(pt, &lp); err != nil {
			// Defensive fallback: never lose the user's data on a decode mismatch.
			out.Value = string(pt)
			return out, nil
		}
		out.Username = lp.Username
		out.Password = lp.Password
	case ItemSecureNote:
		out.Note = string(pt)
	default:
		out.Value = string(pt)
	}
	return out, nil
}
