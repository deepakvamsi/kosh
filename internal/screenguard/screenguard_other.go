//go:build !windows && !darwin && !linux

package screenguard

// Apply is a no-op fallback for platforms without a capture-exclusion implementation.
func Apply(handle uintptr) Result {
	return Result{Supported: false, Applied: false, Note: "capture exclusion not implemented on this platform"}
}
