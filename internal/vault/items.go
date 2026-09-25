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

// keypairPayload is the canonical plaintext shape stored (encrypted) in value_enc for
// ItemKeyPair entries — an access-key / secret-key pair (e.g. AWS IAM credentials).
// Both halves are marshaled to JSON and encrypted together as one value, so a key pair
// is a single vault entry (one row, one audit trail) rather than two linked secrets.
type keypairPayload struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}

// filePayload is the canonical plaintext shape stored (encrypted) in value_enc for
// ItemFile entries: the original filename and the raw file bytes. encoding/json marshals
// Data as base64, so the whole thing is one JSON blob sealed like every other value. The
// filename lives inside the ciphertext too — it is never written to a plaintext column.
// File bytes stay in the Go layer; they are never handed to the UI (see RevealItem, which
// returns only metadata, and RevealFile, used by the save-to-disk path).
type filePayload struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
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

	case ItemKeyPair:
		if strings.TrimSpace(in.AccessKey) == "" {
			return nil, fmt.Errorf("vault: keypair requires an access key")
		}
		if in.SecretKey == "" {
			return nil, fmt.Errorf("vault: keypair requires a secret key")
		}
		b, err := json.Marshal(keypairPayload{AccessKey: in.AccessKey, SecretKey: in.SecretKey})
		if err != nil {
			return nil, fmt.Errorf("vault: encode keypair: %w", err)
		}
		return b, nil

	case ItemFile:
		if strings.TrimSpace(in.FileName) == "" {
			return nil, fmt.Errorf("vault: file requires a name")
		}
		if len(in.Value) == 0 {
			return nil, fmt.Errorf("vault: file requires contents")
		}
		b, err := json.Marshal(filePayload{Name: in.FileName, Data: in.Value})
		if err != nil {
			return nil, fmt.Errorf("vault: encode file: %w", err)
		}
		return b, nil

	default:
		return nil, fmt.Errorf("vault: invalid item type %q", in.ItemType)
	}
}

// RevealedItem is the decoded, type-aware result of revealing an entry. Only the fields
// relevant to ItemType are populated. Callers should treat every string field as
// sensitive and drop references as soon as possible.
type RevealedItem struct {
	ItemType  ItemType
	Value     string // ItemAPIKey: the raw key/token
	Username  string // ItemLogin
	Password  string // ItemLogin
	Note      string // ItemSecureNote
	AccessKey string // ItemKeyPair
	SecretKey string // ItemKeyPair
	FileName  string // ItemFile: original filename (metadata only — never the bytes)
	FileSize  int    // ItemFile: size of the stored file in bytes
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
	case ItemKeyPair:
		var kp keypairPayload
		if err := json.Unmarshal(pt, &kp); err != nil {
			// Defensive fallback: never lose the user's data on a decode mismatch.
			out.Value = string(pt)
			return out, nil
		}
		out.AccessKey = kp.AccessKey
		out.SecretKey = kp.SecretKey
	case ItemFile:
		var fp filePayload
		if err := json.Unmarshal(pt, &fp); err != nil {
			out.Value = string(pt)
			return out, nil
		}
		// Metadata only — the file bytes never leave the Go layer via RevealItem.
		out.FileName = fp.Name
		out.FileSize = len(fp.Data)
		crypto.Zero(fp.Data)
	case ItemSecureNote:
		out.Note = string(pt)
	default:
		out.Value = string(pt)
	}
	return out, nil
}

// RevealFile decrypts an ItemFile entry and returns its original filename and raw bytes,
// for the save-to-disk path only. The caller must zeroize data promptly. The reveal is
// audited exactly like RevealItem (via revealRaw). It errors if the entry is not a file.
func (v *Vault) RevealFile(alias string) (name string, data []byte, err error) {
	itemType, pt, err := v.revealRaw(alias)
	if err != nil {
		return "", nil, err
	}
	defer crypto.Zero(pt)
	if itemType != ItemFile {
		return "", nil, fmt.Errorf("vault: %q is not a file", alias)
	}
	var fp filePayload
	if err := json.Unmarshal(pt, &fp); err != nil {
		return "", nil, fmt.Errorf("vault: decode file: %w", err)
	}
	return fp.Name, fp.Data, nil
}
