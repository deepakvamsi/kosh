package vault

import (
	"testing"
)

func TestListNamesNoDecryption(t *testing.T) {
	v := newInitedVault(t)

	v.AddSecret(AddSecretInput{Alias: "OPENAI_DEV", ProviderKey: "openai", Environment: Dev, Value: []byte("sk-1")})
	v.AddSecret(AddSecretInput{Alias: "AWS_PROD", ProviderKey: "aws", Environment: Prod, Value: []byte("aws-key")})

	names, err := v.ListNames(ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(names))
	}
	for _, n := range names {
		if n.Alias == "" {
			t.Fatal("alias must never be empty")
		}
	}
}

func TestListNamesFilterByProvider(t *testing.T) {
	v := newInitedVault(t)
	v.AddSecret(AddSecretInput{Alias: "OPENAI_DEV", ProviderKey: "openai", Environment: Dev, Value: []byte("1")})
	v.AddSecret(AddSecretInput{Alias: "AWS_DEV", ProviderKey: "aws", Environment: Dev, Value: []byte("2")})

	names, _ := v.ListNames(ListFilter{ProviderKey: "openai"})
	if len(names) != 1 || names[0].Alias != "OPENAI_DEV" {
		t.Fatalf("expected only OPENAI_DEV, got %v", names)
	}
}

func TestListNamesSearch(t *testing.T) {
	v := newInitedVault(t)
	v.AddSecret(AddSecretInput{Alias: "GROQ_DEV", ProviderKey: "groq", Environment: Dev, Value: []byte("1")})
	v.AddSecret(AddSecretInput{Alias: "DEEPSEEK_PROD", ProviderKey: "deepseek", Environment: Prod, Value: []byte("2")})

	names, _ := v.ListNames(ListFilter{Search: "groq"})
	if len(names) != 1 || names[0].Alias != "GROQ_DEV" {
		t.Fatalf("search filter failed: %v", names)
	}
}

func TestTagAndFolder(t *testing.T) {
	v := newInitedVault(t)
	v.AddSecret(AddSecretInput{Alias: "ANTHROPIC_DEV", ProviderKey: "anthropic", Environment: Dev, Value: []byte("ak-1")})

	if err := v.TagSecret("ANTHROPIC_DEV", "ai"); err != nil {
		t.Fatalf("TagSecret: %v", err)
	}
	if err := v.TagSecret("ANTHROPIC_DEV", "llm"); err != nil {
		t.Fatalf("TagSecret: %v", err)
	}

	folderID, err := v.AddFolder("AI Keys", nil)
	if err != nil {
		t.Fatalf("AddFolder: %v", err)
	}
	if err := v.MoveToFolder("ANTHROPIC_DEV", &folderID); err != nil {
		t.Fatalf("MoveToFolder: %v", err)
	}

	names, _ := v.ListNames(ListFilter{})
	s := names[0]
	if s.FolderName != "AI Keys" {
		t.Fatalf("expected folder 'AI Keys', got %q", s.FolderName)
	}
	if len(s.Tags) != 2 {
		t.Fatalf("expected 2 tags, got %v", s.Tags)
	}
}

func TestArchive(t *testing.T) {
	v := newInitedVault(t)
	v.AddSecret(AddSecretInput{Alias: "OLD_KEY", ProviderKey: "github", Environment: Dev, Value: []byte("g")})

	if err := v.ArchiveSecret("OLD_KEY", true); err != nil {
		t.Fatal(err)
	}
	names, _ := v.ListNames(ListFilter{IncludeArchived: false})
	for _, n := range names {
		if n.Alias == "OLD_KEY" {
			t.Fatal("archived secret should not appear in default list")
		}
	}
	all, _ := v.ListNames(ListFilter{IncludeArchived: true})
	found := false
	for _, n := range all {
		if n.Alias == "OLD_KEY" {
			found = true
		}
	}
	if !found {
		t.Fatal("archived secret should appear when IncludeArchived=true")
	}
}
