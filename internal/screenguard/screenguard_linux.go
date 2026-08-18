//go:build linux

package screenguard

// Apply on Linux is a no-op: neither X11 nor Wayland provides a portable,
// app-controllable API to exclude a window from screen capture. Under Wayland the
// compositor mediates capture through portals and applications cannot self-exclude.
// This limitation is documented in docs/SECURITY_ISOLATION.md; complementary controls
// (masked reveal, auto-lock, clipboard auto-clear) still apply.
func Apply(handle uintptr) Result {
	return Result{
		Supported: false,
		Applied:   false,
		Note:      "linux: no portable capture-exclusion API (X11/Wayland); best-effort only",
	}
}
