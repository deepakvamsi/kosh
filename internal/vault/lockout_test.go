package vault

import (
	"path/filepath"
	"testing"
	"time"
)

func TestBackoffSchedule(t *testing.T) {
	if backoffFor(freeUnlockAttempts) != 0 {
		t.Errorf("attempt %d should be free", freeUnlockAttempts)
	}
	if backoffFor(freeUnlockAttempts+1) <= 0 {
		t.Error("first attempt past the free window should lock")
	}
	if backoffFor(100) != 15*time.Minute {
		t.Errorf("backoff should cap at 15m, got %s", backoffFor(100))
	}
	prev := time.Duration(0)
	for i := 1; i <= 12; i++ {
		d := backoffFor(i)
		if d < prev {
			t.Errorf("backoff must be non-decreasing; at %d got %s after %s", i, d, prev)
		}
		prev = d
	}
}

func TestUnlockBackoffLocksOut(t *testing.T) {
	v := newInitedVault(t) // initialized + unlocked with "pw"
	v.Lock()

	// Free attempts: wrong password is rejected but no lockout is imposed.
	for i := 0; i < freeUnlockAttempts; i++ {
		if err := v.Unlock([]byte("nope")); err != ErrWrongPassword {
			t.Fatalf("attempt %d: got %v, want ErrWrongPassword", i+1, err)
		}
		if r := v.LockoutRemaining(); r != 0 {
			t.Fatalf("attempt %d imposed an unexpected %ds lockout", i+1, r)
		}
	}

	// The next failure trips the throttle.
	if err := v.Unlock([]byte("nope")); err != ErrWrongPassword {
		t.Fatalf("triggering attempt: got %v, want ErrWrongPassword", err)
	}
	if v.LockoutRemaining() <= 0 {
		t.Fatal("expected a lockout window after exceeding the free attempts")
	}

	// While locked out, even the CORRECT password is refused (and cheaply, before KDF).
	if err := v.Unlock([]byte("pw")); err != ErrTooManyAttempts {
		t.Fatalf("during lockout: got %v, want ErrTooManyAttempts", err)
	}

	// Once the window elapses, the correct password unlocks and clears the throttle.
	_ = v.writeSetting(settingLockedUntil, "0")
	if err := v.Unlock([]byte("pw")); err != nil {
		t.Fatalf("post-lockout correct unlock: %v", err)
	}
	if fails, _ := v.readLockout(); fails != 0 {
		t.Fatalf("failure counter not reset after a successful unlock: %d", fails)
	}
}

// TestLockoutSurvivesReopen is the property that makes the throttle meaningful: the
// counter lives in the DB, so closing and reopening the vault (an app restart) must not
// reset it.
func TestLockoutSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")

	v, err := Open(path, "ui")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := v.Init([]byte("pw")); err != nil {
		t.Fatalf("init: %v", err)
	}
	v.Lock()
	for i := 0; i < freeUnlockAttempts+1; i++ {
		v.Unlock([]byte("nope"))
	}
	if v.LockoutRemaining() <= 0 {
		t.Fatal("expected a lockout before reopen")
	}
	v.Close()

	v2, err := Open(path, "ui")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer v2.Close()
	if v2.LockoutRemaining() <= 0 {
		t.Fatal("lockout did not survive reopen — a restart bypasses the throttle")
	}
	if fails, _ := v2.readLockout(); fails != freeUnlockAttempts+1 {
		t.Fatalf("failure counter lost across reopen: got %d", fails)
	}
}
