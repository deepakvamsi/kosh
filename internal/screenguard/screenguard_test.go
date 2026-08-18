package screenguard

import "testing"

// TestApplyReturnsResult verifies Apply returns a well-formed Result on the current
// platform without panicking. On Windows/macOS it should report Supported=true; on
// Linux Supported=false. We do not assert Applied because there is no real window
// handle in a unit test.
func TestApplyReturnsResult(t *testing.T) {
	res := Apply(0)
	if res.Note == "" {
		t.Fatal("expected a non-empty explanatory note")
	}
}
