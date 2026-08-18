package vault

import (
	"testing"
	"time"
)

// TestTouchResetsIdleTimer verifies that recording activity via Touch (called by the UI
// heartbeat) pushes back the idle deadline so the backend auto-lock does not fire. The
// basic auto-lock behaviour itself is covered by TestAutoLockIfIdle in vault_test.go.
func TestTouchResetsIdleTimer(t *testing.T) {
	v := newInitedVault(t)
	time.Sleep(5 * time.Millisecond)

	v.Touch() // reset the activity timestamp to "now"

	if v.AutoLockIfIdle(time.Hour) {
		t.Fatal("Touch should have reset the idle timer")
	}
	if !v.Unlocked() {
		t.Fatal("vault should remain unlocked after Touch")
	}

	// Touch on a locked vault must be a harmless no-op.
	v.Lock()
	v.Touch()
	if v.Unlocked() {
		t.Fatal("Touch must not unlock a locked vault")
	}
}
