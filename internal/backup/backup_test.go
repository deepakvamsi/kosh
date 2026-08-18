package backup

import (
	"bytes"
	"testing"

	"kosh/internal/storage"
	"kosh/internal/vault"
)

func newVault(t *testing.T) (*storage.DB, *vault.Vault) {
	t.Helper()
	db, err := storage.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.OpenDB(db, "ui")
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := v.Init([]byte("pw")); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close(); db.Close() })
	return db, v
}

func TestExportImportRoundTrip(t *testing.T) {
	db, v := newVault(t)

	_, err := v.AddSecret(vault.AddSecretInput{
		Alias: "OPENAI_DEV", ProviderKey: "openai", Environment: vault.Dev,
		Value: []byte("sk-round-trip"),
	})
	if err != nil {
		t.Fatal(err)
	}

	archive, err := Export(db.SQL(), []byte("pw"))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if len(archive) == 0 {
		t.Fatal("archive must not be empty")
	}
	if bytes.Contains(archive, []byte("sk-round-trip")) {
		t.Fatal("archive must not contain plaintext secret")
	}

	db2, v2 := newVault(t)
	v2.Lock()

	if err := Import(db2.SQL(), archive, []byte("pw")); err != nil {
		t.Fatalf("Import: %v", err)
	}

	if err := v2.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	secrets, err := v2.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range secrets {
		if s.Alias == "OPENAI_DEV" {
			found = true
		}
	}
	if !found {
		t.Fatal("OPENAI_DEV not found after import")
	}
}

// TestCrossVaultRestoreDecryptsValue is the portability regression test: a backup made
// on one vault must be restorable onto a *different* vault (with its own, unrelated DEK)
// and the secret VALUE must decrypt afterwards. This exercises both fixes — restoring
// the wrapped DEK/key material, and preserving each secret's row id (the id is bound as
// AEAD associated data, so a changed id would make Reveal fail the auth check).
func TestCrossVaultRestoreDecryptsValue(t *testing.T) {
	db, v := newVault(t)
	const plaintext = "sk-cross-vault-secret-value"
	if _, err := v.AddSecret(vault.AddSecretInput{
		Alias: "OPENAI_DEV", ProviderKey: "openai", Environment: vault.Dev,
		Value: []byte(plaintext),
	}); err != nil {
		t.Fatal(err)
	}

	archive, err := Export(db.SQL(), []byte("pw"))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	// db2 is a completely separate vault with a different random DEK.
	db2, v2 := newVault(t)
	v2.Lock()
	if err := Import(db2.SQL(), archive, []byte("pw")); err != nil {
		t.Fatalf("Import: %v", err)
	}

	// The restored vault must unlock with the ORIGINAL master password ...
	if err := v2.Unlock([]byte("pw")); err != nil {
		t.Fatalf("Unlock after restore: %v", err)
	}
	// ... and the value must decrypt back to exactly what we stored.
	got, err := v2.Reveal("OPENAI_DEV")
	if err != nil {
		t.Fatalf("Reveal after restore: %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("revealed value = %q, want %q", got, plaintext)
	}
}

// TestBackupPreservesFoldersTagsCustomFields is the completeness regression test: a
// backup must carry the full organisational state — folder membership, tags, and custom
// fields — and restore it faithfully onto a fresh vault, alongside the decryptable value.
func TestBackupPreservesFoldersTagsCustomFields(t *testing.T) {
	db, v := newVault(t)

	fid, err := v.AddFolder("Production", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.AddSecret(vault.AddSecretInput{
		Alias: "STRIPE_PROD", ProviderKey: "custom", Environment: vault.Prod,
		Value: []byte("sk_live_xyz"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := v.MoveToFolder("STRIPE_PROD", &fid); err != nil {
		t.Fatal(err)
	}
	if err := v.TagSecret("STRIPE_PROD", "billing"); err != nil {
		t.Fatal(err)
	}
	if err := v.TagSecret("STRIPE_PROD", "pci"); err != nil {
		t.Fatal(err)
	}
	const customJSON = `{"account_id":"acct_123","team":"payments"}`
	if err := v.SetCustomFields("STRIPE_PROD", customJSON); err != nil {
		t.Fatal(err)
	}

	archive, err := Export(db.SQL(), []byte("pw"))
	if err != nil {
		t.Fatalf("Export: %v", err)
	}

	db2, v2 := newVault(t)
	v2.Lock()
	if err := Import(db2.SQL(), archive, []byte("pw")); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if err := v2.Unlock([]byte("pw")); err != nil {
		t.Fatal(err)
	}

	summaries, err := v2.ListNames(vault.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var got *vault.SecretSummary
	for i := range summaries {
		if summaries[i].Alias == "STRIPE_PROD" {
			got = &summaries[i]
		}
	}
	if got == nil {
		t.Fatal("STRIPE_PROD missing after restore")
	}
	if got.FolderName != "Production" {
		t.Fatalf("folder = %q, want %q", got.FolderName, "Production")
	}
	if got.CustomFields != customJSON {
		t.Fatalf("custom fields = %q, want %q", got.CustomFields, customJSON)
	}
	tagSet := map[string]bool{}
	for _, tg := range got.Tags {
		tagSet[tg] = true
	}
	if len(got.Tags) != 2 || !tagSet["billing"] || !tagSet["pci"] {
		t.Fatalf("tags = %v, want [billing pci]", got.Tags)
	}

	val, err := v2.Reveal("STRIPE_PROD")
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if string(val) != "sk_live_xyz" {
		t.Fatalf("value = %q, want %q", val, "sk_live_xyz")
	}
}

func TestImportWrongPasswordFails(t *testing.T) {
	db, v := newVault(t)
	v.AddSecret(vault.AddSecretInput{
		Alias: "AWS_DEV", ProviderKey: "aws", Environment: vault.Dev, Value: []byte("k"),
	})

	archive, _ := Export(db.SQL(), []byte("pw"))

	db2, _ := newVault(t)
	if err := Import(db2.SQL(), archive, []byte("wrong")); err != ErrBadBackup {
		t.Fatalf("expected ErrBadBackup for wrong password, got %v", err)
	}
}

func TestImportTamperedArchiveFails(t *testing.T) {
	db, _ := newVault(t)
	archive, _ := Export(db.SQL(), []byte("pw"))

	archive[len(archive)-1] ^= 0xFF

	db2, _ := newVault(t)
	if err := Import(db2.SQL(), archive, []byte("pw")); err != ErrBadBackup {
		t.Fatalf("expected ErrBadBackup for tampered archive, got %v", err)
	}
}
