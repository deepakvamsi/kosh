package vault

import (
	"errors"
	"testing"

	"kosh/internal/audit"
)

func TestVerifyPasswordAcceptsCorrectPassword(t *testing.T) {
	v := newInitedVault(t)
	if err := v.VerifyPassword([]byte("pw")); err != nil {
		t.Fatalf("VerifyPassword with correct password: %v", err)
	}
	// Re-auth must not disturb the lock state — the caller is mid-operation.
	if !v.Unlocked() {
		t.Fatal("vault became locked after a successful re-auth")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	v := newInitedVault(t)
	if err := v.VerifyPassword([]byte("not-pw")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("want ErrWrongPassword, got %v", err)
	}
	if !v.Unlocked() {
		t.Fatal("a failed re-auth must not lock the vault out from under the caller")
	}
}

func TestVerifyPasswordRequiresUnlockedVault(t *testing.T) {
	v := newInitedVault(t)
	v.Lock()
	if err := v.VerifyPassword([]byte("pw")); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked on a locked vault, got %v", err)
	}
}

// A failed re-auth must not consume the unlock budget: the vault is already unlocked,
// so throttling here would only lock the legitimate user out of their own prompt.
func TestVerifyPasswordDoesNotTouchLockout(t *testing.T) {
	v := newInitedVault(t)
	for i := 0; i < 10; i++ {
		_ = v.VerifyPassword([]byte("wrong"))
	}
	if fails, until := v.readLockout(); fails != 0 || until != 0 {
		t.Fatalf("re-auth mutated lockout state: fails=%d until=%d", fails, until)
	}
	if got := v.LockoutRemaining(); got != 0 {
		t.Fatalf("LockoutRemaining = %d, want 0", got)
	}
}

// Both outcomes must land in the audit log — a privileged-operation gate that leaves
// no trace is not auditable.
func TestVerifyPasswordIsAudited(t *testing.T) {
	v := newInitedVault(t)
	if err := v.VerifyPassword([]byte("pw")); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	_ = v.VerifyPassword([]byte("wrong"))

	records, err := audit.List(v.DB().SQL(), 100)
	if err != nil {
		t.Fatalf("audit.List: %v", err)
	}
	var allow, deny int
	for _, r := range records {
		if r.Action != "reauth" {
			continue
		}
		switch r.Outcome {
		case audit.Allow:
			allow++
		case audit.Deny:
			deny++
		}
	}
	if allow != 1 || deny != 1 {
		t.Fatalf("reauth audit records: allow=%d deny=%d, want 1 and 1", allow, deny)
	}
	if _, err := audit.VerifyChain(v.DB().SQL()); err != nil {
		t.Fatalf("audit chain broken after re-auth: %v", err)
	}
}
