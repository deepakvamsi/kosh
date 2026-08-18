package vault

import (
	"testing"
)

func TestRecoveryKeyRoundTrip(t *testing.T) {
	v := newInitedVault(t) // unlocked, master password "pw"

	if _, err := v.AddSecret(AddSecretInput{
		Alias: "OPENAI_DEV", ProviderKey: "openai", Environment: Dev, Value: []byte("sk-secret"),
	}); err != nil {
		t.Fatal(err)
	}

	code, err := v.GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey: %v", err)
	}
	if code == "" {
		t.Fatal("recovery code must not be empty")
	}
	if has, _ := v.HasRecoveryKey(); !has {
		t.Fatal("HasRecoveryKey should be true after generating one")
	}

	v.Lock()

	// Recover using the code and set a brand-new master password.
	const newPass = "brand-new-master-pass"
	if err := v.RecoverWithKey(code, []byte(newPass)); err != nil {
		t.Fatalf("RecoverWithKey: %v", err)
	}
	if !v.Unlocked() {
		t.Fatal("vault should be unlocked after recovery")
	}

	// The DEK is intact, so the secret still decrypts.
	val, err := v.Reveal("OPENAI_DEV")
	if err != nil {
		t.Fatalf("Reveal after recovery: %v", err)
	}
	if string(val) != "sk-secret" {
		t.Fatalf("value = %q, want %q", val, "sk-secret")
	}

	// The OLD password no longer works; the NEW one does.
	v.Lock()
	if err := v.Unlock([]byte("pw")); err != ErrWrongPassword {
		t.Fatalf("old password should fail, got %v", err)
	}
	if err := v.Unlock([]byte(newPass)); err != nil {
		t.Fatalf("new password should unlock, got %v", err)
	}
}

func TestRecoverWithWrongKey(t *testing.T) {
	v := newInitedVault(t)
	if _, err := v.GenerateRecoveryKey(); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.RecoverWithKey("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH", []byte("x")); err != ErrWrongRecoveryKey {
		t.Fatalf("expected ErrWrongRecoveryKey, got %v", err)
	}
	// A failed recovery must not have unlocked or re-keyed the vault.
	if v.Unlocked() {
		t.Fatal("vault should remain locked after a failed recovery")
	}
	if err := v.Unlock([]byte("pw")); err != nil {
		t.Fatalf("original password should still work, got %v", err)
	}
}

func TestRecoverWithoutRecoveryKey(t *testing.T) {
	v := newInitedVault(t)
	v.Lock()
	if err := v.RecoverWithKey("AAAA-BBBB", []byte("x")); err != ErrNoRecoveryKey {
		t.Fatalf("expected ErrNoRecoveryKey, got %v", err)
	}
}

func TestHasRecoveryKeyDefaultsFalse(t *testing.T) {
	v := newInitedVault(t)
	if has, err := v.HasRecoveryKey(); err != nil || has {
		t.Fatalf("expected (false,nil), got (%v,%v)", has, err)
	}
}
