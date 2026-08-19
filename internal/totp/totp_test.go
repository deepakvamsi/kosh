package totp

import (
	"testing"
	"time"
)

// TestRFC6238Vector checks a known RFC 6238 test vector: the ASCII seed
// "12345678901234567890" (base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") yields the 8-digit
// SHA1 TOTP 94287082 at T=59s, i.e. the 6-digit code 287082.
func TestRFC6238Vector(t *testing.T) {
	const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, remaining, err := Code(seed, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if code != "287082" {
		t.Errorf("code = %q, want 287082", code)
	}
	if remaining != 1 { // 59 % 30 = 29 → 1s left in the window
		t.Errorf("remaining = %d, want 1", remaining)
	}
}

func TestNormalizeAndValidate(t *testing.T) {
	if got := Normalize("gezd gnbv gy3t qojq"); got != "GEZDGNBVGY3TQOJQ" {
		t.Errorf("Normalize = %q", got)
	}
	if err := Validate("GEZDGNBVGY3TQOJQ"); err != nil {
		t.Errorf("valid seed rejected: %v", err)
	}
	if err := Validate("not base32 !!!"); err == nil {
		t.Error("invalid seed accepted")
	}
	if err := Validate(""); err == nil {
		t.Error("empty seed accepted")
	}
}

func TestCodeRotates(t *testing.T) {
	const seed = "GEZDGNBVGY3TQOJQ"
	a, _, _ := Code(seed, time.Unix(0, 0))
	b, _, _ := Code(seed, time.Unix(30, 0))
	if a == b {
		t.Error("code should differ across adjacent 30s windows")
	}
}
