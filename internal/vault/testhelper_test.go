package vault

import "testing"

// newVault returns a fresh in-memory vault without initializing it.
// Tests that need an already-initialized vault must call v.Init() themselves
// or use newInitedVault.
func newVault(t *testing.T) *Vault {
	t.Helper()
	v, err := Open(":memory:", "ui")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { v.Close() })
	return v
}

// newInitedVault returns a fresh in-memory vault already initialized and unlocked
// with password "pw". Use for tests that start from an unlocked vault.
func newInitedVault(t *testing.T) *Vault {
	t.Helper()
	v := newVault(t)
	if err := v.Init([]byte("pw")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return v
}
