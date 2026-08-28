package crypto

import (
	"testing"
	"time"
)

func TestCalibrateStaysWithinBounds(t *testing.T) {
	for _, target := range []time.Duration{
		1 * time.Nanosecond, // absurdly tight
		100 * time.Millisecond,
		DefaultCalibrationTarget,
		30 * time.Second, // absurdly generous
		0,                // invalid → falls back to the default target
		-1,
	} {
		p := CalibrateKDFParams(target)
		if !ValidKDFParams(p) {
			t.Errorf("target %v produced out-of-range params %+v", target, p)
		}
		if p.MemoryKiB < MinMemoryKiB {
			t.Errorf("target %v produced params weaker than the floor: %+v", target, p)
		}
		if p.MemoryKiB > MaxMemoryKiB || p.Time > MaxTime {
			t.Errorf("target %v exceeded the ceiling: %+v", target, p)
		}
	}
}

// Calibration must never produce something weaker than the historical default, or an
// upgrade could silently downgrade a vault on a slow machine.
func TestCalibrateNeverWeakerThanDefault(t *testing.T) {
	def := DefaultKDFParams()
	for _, target := range []time.Duration{1 * time.Nanosecond, 50 * time.Millisecond, 5 * time.Second} {
		p := CalibrateKDFParams(target)
		if !AtLeastAsStrong(def, p) {
			t.Errorf("target %v produced %+v, weaker than the default %+v", target, p, def)
		}
	}
}

// A tight budget must land exactly on the floor, not below it.
func TestCalibrateTightBudgetReturnsFloor(t *testing.T) {
	p := CalibrateKDFParams(1 * time.Nanosecond)
	if p.MemoryKiB != MinMemoryKiB || p.Time != MinTime {
		t.Fatalf("got %+v, want the floor (t=%d m=%d)", p, MinTime, MinMemoryKiB)
	}
}

// Calibrated parameters must actually derive a working key.
func TestCalibratedParamsDeriveUsableKey(t *testing.T) {
	p := CalibrateKDFParams(200 * time.Millisecond)
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	k1 := DeriveKey([]byte("pw"), salt, p)
	k2 := DeriveKey([]byte("pw"), salt, p)
	if len(k1) != KeyLen {
		t.Fatalf("key length %d, want %d", len(k1), KeyLen)
	}
	if string(k1) != string(k2) {
		t.Fatal("derivation is not deterministic for identical inputs")
	}
	k3 := DeriveKey([]byte("other"), salt, p)
	if string(k1) == string(k3) {
		t.Fatal("different passwords produced the same key")
	}
}

func TestAtLeastAsStrong(t *testing.T) {
	base := KDFParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}
	cases := []struct {
		name string
		b    KDFParams
		want bool
	}{
		{"identical", base, true},
		{"more memory", KDFParams{Time: 3, MemoryKiB: 128 * 1024, Threads: 4}, true},
		{"more time", KDFParams{Time: 4, MemoryKiB: 64 * 1024, Threads: 4}, true},
		{"less memory", KDFParams{Time: 3, MemoryKiB: 32 * 1024, Threads: 4}, false},
		{"less time", KDFParams{Time: 2, MemoryKiB: 64 * 1024, Threads: 4}, false},
		{"more memory but less time", KDFParams{Time: 2, MemoryKiB: 512 * 1024, Threads: 4}, false},
	}
	for _, tc := range cases {
		if got := AtLeastAsStrong(base, tc.b); got != tc.want {
			t.Errorf("%s: AtLeastAsStrong(%+v, %+v) = %v, want %v", tc.name, base, tc.b, got, tc.want)
		}
	}
}

func TestStrengthenWorthwhile(t *testing.T) {
	cur := KDFParams{Time: 3, MemoryKiB: 256 * 1024, Threads: 4}
	cases := []struct {
		name string
		sug  KDFParams
		want bool
	}{
		{"identical (jitter zero)", cur, false},
		{"tiny memory jitter up", KDFParams{Time: 3, MemoryKiB: 256*1024 + 4*1024, Threads: 4}, false},
		{"tiny memory jitter down", KDFParams{Time: 3, MemoryKiB: 256*1024 - 4*1024, Threads: 4}, false},
		{"25% more memory", KDFParams{Time: 3, MemoryKiB: 320 * 1024, Threads: 4}, true},
		{"more time", KDFParams{Time: 4, MemoryKiB: 256 * 1024, Threads: 4}, true},
		{"less memory", KDFParams{Time: 3, MemoryKiB: 128 * 1024, Threads: 4}, false},
	}
	for _, tc := range cases {
		if got := StrengthenWorthwhile(cur, tc.sug); got != tc.want {
			t.Errorf("%s: StrengthenWorthwhile(%+v,%+v)=%v want %v", tc.name, cur, tc.sug, got, tc.want)
		}
	}
}

func TestValidKDFParams(t *testing.T) {
	cases := []struct {
		name string
		p    KDFParams
		want bool
	}{
		{"floor", KDFParams{Time: MinTime, MemoryKiB: MinMemoryKiB, Threads: 4}, true},
		{"ceiling", KDFParams{Time: MaxTime, MemoryKiB: MaxMemoryKiB, Threads: 4}, true},
		{"below memory floor", KDFParams{Time: 3, MemoryKiB: 8 * 1024, Threads: 4}, false},
		{"above memory ceiling", KDFParams{Time: 3, MemoryKiB: 2 * 1024 * 1024, Threads: 4}, false},
		{"time zero", KDFParams{Time: 0, MemoryKiB: MinMemoryKiB, Threads: 4}, false},
		{"time too high", KDFParams{Time: 99, MemoryKiB: MinMemoryKiB, Threads: 4}, false},
		{"threads zero", KDFParams{Time: 3, MemoryKiB: MinMemoryKiB, Threads: 0}, false},
		{"zero value", KDFParams{}, false},
	}
	for _, tc := range cases {
		if got := ValidKDFParams(tc.p); got != tc.want {
			t.Errorf("%s: ValidKDFParams(%+v) = %v, want %v", tc.name, tc.p, got, tc.want)
		}
	}
}
