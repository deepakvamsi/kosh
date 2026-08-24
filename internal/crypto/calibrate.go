package crypto

import "time"

// Argon2id cost bounds for calibration.
//
// The floor is the historical default (t=3, 64 MiB, p=4): calibration may only make a
// vault stronger, never weaker, so a slow machine keeps the parameters every existing
// vault already used rather than negotiating itself down.
//
// The ceiling exists because the cost is paid on every unlock, on the user's own machine,
// with no way to opt out short of the recovery key. 512 MiB is well above what a
// commodity attacker amortises cheaply and still leaves headroom on an 8 GiB laptop; past
// that, an unlock risks swapping, which is both slow and a way for key material to reach
// the page file.
const (
	MinMemoryKiB = 64 * 1024  // 64 MiB
	MaxMemoryKiB = 512 * 1024 // 512 MiB
	MinTime      = 3
	MaxTime      = 10
)

// DefaultCalibrationTarget is how long an unlock should take on the machine that created
// the vault. Long enough to cost an offline attacker dearly, short enough that a user
// unlocking several times a day does not start resenting it.
const DefaultCalibrationTarget = 750 * time.Millisecond

// CalibrateKDFParams measures Argon2id on THIS machine and returns the strongest
// parameters whose derivation still completes within target.
//
// Why this exists: `vault.db` is a file. An attacker who copies it can attack the master
// password offline as fast as their hardware allows, and the Argon2id cost is the only
// thing in their way (see docs/THREAT_MODEL.md). A fixed 64 MiB default was chosen for
// the slowest machine anyone might run Kosh on, which means every faster machine was
// leaving protection unclaimed.
//
// Memory is scaled first because memory hardness is what degrades an attacker's GPU and
// ASIC advantage; time passes are only increased once memory has hit the ceiling. The
// result is clamped to [MinMemoryKiB, MaxMemoryKiB] and [MinTime, MaxTime], so a
// pathologically slow or fast measurement cannot produce parameters outside a range that
// has been reasoned about.
//
// Calibration is measurement, not a security decision: a hostile or noisy result can only
// move the parameters within those bounds, and the floor equals the old default.
func CalibrateKDFParams(target time.Duration) KDFParams {
	if target <= 0 {
		target = DefaultCalibrationTarget
	}

	p := KDFParams{Time: MinTime, MemoryKiB: MinMemoryKiB, Threads: DefaultKDFParams().Threads}

	elapsed := measureDerive(p)
	if elapsed <= 0 || elapsed >= target {
		// Already at or over budget at the floor — this machine gets the floor.
		return p
	}

	// Argon2id cost is close to linear in memory, so one measurement gives a usable
	// estimate. Scale, clamp, then verify and back off if the estimate overshot.
	scaled := float64(p.MemoryKiB) * (float64(target) / float64(elapsed))
	mem := uint32(scaled)
	if mem > MaxMemoryKiB {
		mem = MaxMemoryKiB
	}
	if mem < MinMemoryKiB {
		mem = MinMemoryKiB
	}
	// Round down to a whole MiB so stored parameters stay legible.
	mem = (mem / 1024) * 1024
	if mem < MinMemoryKiB {
		mem = MinMemoryKiB
	}
	p.MemoryKiB = mem

	// One verification pass. If the estimate overshot the budget, step memory back
	// rather than shipping parameters that make every unlock feel broken.
	for p.MemoryKiB > MinMemoryKiB {
		if measureDerive(p) <= target {
			break
		}
		next := p.MemoryKiB / 2
		if next < MinMemoryKiB {
			next = MinMemoryKiB
		}
		p.MemoryKiB = next
	}

	// Memory is maxed and there is still budget left: spend it on time passes.
	if p.MemoryKiB == MaxMemoryKiB {
		for p.Time < MaxTime {
			probe := p
			probe.Time = p.Time + 1
			if measureDerive(probe) > target {
				break
			}
			p = probe
		}
	}

	return p
}

// measureDerive times one Argon2id derivation with the given parameters.
func measureDerive(p KDFParams) time.Duration {
	// Fixed, non-secret inputs: only the cost is being measured.
	password := []byte("kosh-calibration-probe")
	salt := make([]byte, SaltLen)

	start := time.Now()
	key := DeriveKey(password, salt, p)
	elapsed := time.Since(start)
	Zero(key)
	return elapsed
}

// AtLeastAsStrong reports whether b is at least as costly as a in every dimension. Used
// to refuse a re-key that would weaken an existing vault.
func AtLeastAsStrong(a, b KDFParams) bool {
	return b.Time >= a.Time && b.MemoryKiB >= a.MemoryKiB
}

// ValidKDFParams reports whether p is inside the bounds calibration will ever produce.
// Parameters arriving from outside (a hand-edited database, a bound API call) are checked
// against this before use.
func ValidKDFParams(p KDFParams) bool {
	return p.Time >= MinTime && p.Time <= MaxTime &&
		p.MemoryKiB >= MinMemoryKiB && p.MemoryKiB <= MaxMemoryKiB &&
		p.Threads >= 1 && p.Threads <= 16
}
