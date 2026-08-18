package vault

import (
	"strings"
	"testing"
)

func TestAddLoginAndRevealItem(t *testing.T) {
	v := newInitedVault(t)
	if _, err := v.AddSecret(AddSecretInput{
		Alias: "github-login", ItemType: ItemLogin, ProviderKey: "github", Environment: Dev,
		Username: "octocat@example.com", Password: "hunter2-Sup3r",
	}); err != nil {
		t.Fatalf("AddSecret login: %v", err)
	}
	r, err := v.RevealItem("github-login")
	if err != nil {
		t.Fatalf("RevealItem: %v", err)
	}
	if r.ItemType != ItemLogin {
		t.Errorf("item type = %q, want login", r.ItemType)
	}
	if r.Username != "octocat@example.com" || r.Password != "hunter2-Sup3r" {
		t.Errorf("login round trip: got (%q, %q)", r.Username, r.Password)
	}
}

// TestLoginSecretsNeverStoredInPlaintextColumns is the security guarantee for the item
// model: a login's username and password live ONLY inside the encrypted value_enc blob,
// never in any queryable/plaintext column.
func TestLoginSecretsNeverStoredInPlaintextColumns(t *testing.T) {
	v := newInitedVault(t)
	const user = "octocat@example.com"
	const pass = "hunter2-Sup3r-Secret"
	if _, err := v.AddSecret(AddSecretInput{
		Alias: "gh", ItemType: ItemLogin, ProviderKey: "github", Environment: Prod,
		Description: "my github", Username: user, Password: pass,
	}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}

	var alias, itemType, env, desc, custom string
	var valueEnc, valueHash []byte
	row := v.db.SQL().QueryRow(
		`SELECT alias,item_type,environment,COALESCE(description,''),COALESCE(custom_fields,'{}'),value_enc,value_hash
		   FROM secrets WHERE alias='gh'`)
	if err := row.Scan(&alias, &itemType, &env, &desc, &custom, &valueEnc, &valueHash); err != nil {
		t.Fatalf("scan: %v", err)
	}

	plaintextCols := map[string]string{
		"alias": alias, "item_type": itemType, "environment": env,
		"description": desc, "custom_fields": custom,
	}
	for name, col := range plaintextCols {
		if strings.Contains(col, user) || strings.Contains(col, pass) {
			t.Errorf("plaintext column %q leaked secret material: %q", name, col)
		}
	}
	if strings.Contains(string(valueEnc), user) || strings.Contains(string(valueEnc), pass) {
		t.Error("value_enc must be ciphertext but contains plaintext username/password")
	}
	if strings.Contains(string(valueHash), user) || strings.Contains(string(valueHash), pass) {
		t.Error("value_hash must be a keyed hash but contains plaintext")
	}
}

func TestSecureNoteRoundTrip(t *testing.T) {
	v := newInitedVault(t)
	const body = "recovery phrase: correct horse battery staple"
	if _, err := v.AddSecret(AddSecretInput{
		Alias: "note1", ItemType: ItemSecureNote, ProviderKey: "custom", Environment: Prod, Note: body,
	}); err != nil {
		t.Fatalf("AddSecret note: %v", err)
	}
	r, err := v.RevealItem("note1")
	if err != nil {
		t.Fatalf("RevealItem: %v", err)
	}
	if r.ItemType != ItemSecureNote || r.Note != body {
		t.Errorf("note round trip failed: %+v", r)
	}
}

// TestAPIKeyBackwardCompatible confirms the pre-item-type path is unchanged: a caller
// that sets no ItemType stores a raw key, and both Reveal and RevealItem return it.
func TestAPIKeyBackwardCompatible(t *testing.T) {
	v := newInitedVault(t)
	if _, err := v.AddSecret(AddSecretInput{
		Alias: "OPENAI", ProviderKey: "openai", Environment: Dev, Value: []byte("sk-abc123"),
	}); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	b, err := v.Reveal("OPENAI")
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if string(b) != "sk-abc123" {
		t.Errorf("Reveal = %q, want sk-abc123", b)
	}
	r, err := v.RevealItem("OPENAI")
	if err != nil {
		t.Fatalf("RevealItem: %v", err)
	}
	if r.ItemType != ItemAPIKey || r.Value != "sk-abc123" {
		t.Errorf("RevealItem = %+v", r)
	}
}

func TestItemValidation(t *testing.T) {
	v := newInitedVault(t)
	cases := []struct {
		name string
		in   AddSecretInput
	}{
		{"login missing password", AddSecretInput{Alias: "a", ItemType: ItemLogin, ProviderKey: "github", Environment: Dev, Username: "u"}},
		{"login missing username", AddSecretInput{Alias: "b", ItemType: ItemLogin, ProviderKey: "github", Environment: Dev, Password: "p"}},
		{"note missing body", AddSecretInput{Alias: "c", ItemType: ItemSecureNote, ProviderKey: "custom", Environment: Dev}},
		{"api_key missing value", AddSecretInput{Alias: "d", ItemType: ItemAPIKey, ProviderKey: "openai", Environment: Dev}},
		{"unknown item type", AddSecretInput{Alias: "e", ItemType: "totp", ProviderKey: "openai", Environment: Dev, Value: []byte("x")}},
	}
	for _, tc := range cases {
		if _, err := v.AddSecret(tc.in); err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}
