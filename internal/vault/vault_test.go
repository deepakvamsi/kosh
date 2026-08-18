package vault

import (
	"bytes"
	"testing"
	"time"
)

func TestInitUnlockLock(t *testing.T) {
	v := newVault(t)
	pw := []byte("master-pw-123")
	if err := v.Init(append([]byte(nil), pw...)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !v.Unlocked() {
		t.Fatal("vault should be unlocked after Init")
	}
	v.Lock()
	if v.Unlocked() {
		t.Fatal("vault should be locked after Lock")
	}
	if err := v.Unlock(append([]byte(nil), pw...)); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if !v.Unlocked() {
		t.Fatal("vault should be unlocked after Unlock")
	}
}

func TestInitTwiceFails(t *testing.T) {
	v := newVault(t)
	if err := v.Init([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	if err := v.Init([]byte("pw")); err != ErrAlreadyInitialized {
		t.Fatalf("expected ErrAlreadyInitialized, got %v", err)
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	v := newVault(t)
	if err := v.Init([]byte("right")); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.Unlock([]byte("wrong")); err != ErrWrongPassword {
		t.Fatalf("expected ErrWrongPassword, got %v", err)
	}
}

func TestUnlockNotInitialized(t *testing.T) {
	v := newVault(t)
	if err := v.Unlock([]byte("pw")); err != ErrNotInitialized {
		t.Fatalf("expected ErrNotInitialized, got %v", err)
	}
}

func TestAddRevealRoundTrip(t *testing.T) {
	v := newInitedVault(t)
	secret := []byte("sk-openai-abc123")
	id, err := v.AddSecret(AddSecretInput{
		Alias:       "OPENAI_DEV",
		ProviderKey: "openai",
		Environment: Dev,
		Value:       append([]byte(nil), secret...),
	})
	if err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id")
	}
	got, err := v.Reveal("OPENAI_DEV")
	if err != nil {
		t.Fatalf("Reveal: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("reveal mismatch: got %q want %q", got, secret)
	}
}

func TestCiphertextNotPlaintextOnDisk(t *testing.T) {
	v := newInitedVault(t)
	secret := []byte("super-secret-value-xyz")
	v.AddSecret(AddSecretInput{Alias: "AWS_PROD", ProviderKey: "aws", Environment: Prod, Value: append([]byte(nil), secret...)})
	var blob []byte
	if err := v.db.SQL().QueryRow(`SELECT value_enc FROM secrets WHERE alias='AWS_PROD'`).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, secret) {
		t.Fatal("stored value_enc must not contain plaintext")
	}
}

func TestRevealWhenLockedFails(t *testing.T) {
	v := newInitedVault(t)
	v.AddSecret(AddSecretInput{Alias: "GITHUB_DEV", ProviderKey: "github", Environment: Dev, Value: []byte("ghp_x")})
	v.Lock()
	if _, err := v.Reveal("GITHUB_DEV"); err != ErrLocked {
		t.Fatalf("expected ErrLocked, got %v", err)
	}
}

func TestUpdateValue(t *testing.T) {
	v := newInitedVault(t)
	v.AddSecret(AddSecretInput{Alias: "GROQ_DEV", ProviderKey: "groq", Environment: Dev, Value: []byte("old")})
	if err := v.UpdateValue("GROQ_DEV", []byte("new-value")); err != nil {
		t.Fatalf("UpdateValue: %v", err)
	}
	got, err := v.Reveal("GROQ_DEV")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new-value" {
		t.Fatalf("expected updated value, got %q", got)
	}
}

func TestDeleteSecret(t *testing.T) {
	v := newInitedVault(t)
	v.AddSecret(AddSecretInput{Alias: "REDIS_DEV", ProviderKey: "redis", Environment: Dev, Value: []byte("x")})
	if err := v.DeleteSecret("REDIS_DEV"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := v.Reveal("REDIS_DEV"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestListSecrets(t *testing.T) {
	v := newInitedVault(t)
	v.AddSecret(AddSecretInput{Alias: "A_DEV", ProviderKey: "openai", Environment: Dev, Value: []byte("1")})
	v.AddSecret(AddSecretInput{Alias: "B_PROD", ProviderKey: "aws", Environment: Prod, Value: []byte("2")})
	list, err := v.ListSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(list))
	}
}

func TestInvalidEnvironmentRejected(t *testing.T) {
	v := newInitedVault(t)
	_, err := v.AddSecret(AddSecretInput{Alias: "BAD", ProviderKey: "openai", Environment: "production", Value: []byte("x")})
	if err == nil {
		t.Fatal("expected error for invalid environment")
	}
}

func TestUnknownProviderRejected(t *testing.T) {
	v := newInitedVault(t)
	_, err := v.AddSecret(AddSecretInput{Alias: "X", ProviderKey: "nope", Environment: Dev, Value: []byte("x")})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestAutoLockIfIdle(t *testing.T) {
	v := newInitedVault(t)
	if locked := v.AutoLockIfIdle(time.Hour); locked {
		t.Fatal("should not auto-lock before idle threshold")
	}
	if locked := v.AutoLockIfIdle(0); !locked {
		t.Fatal("should auto-lock at zero idle threshold")
	}
	if v.Unlocked() {
		t.Fatal("vault should be locked after auto-lock")
	}
}
