// Package screenguard requests OS-level exclusion of the application window from
// screen capture (screenshots and most screen recorders).
//
// This is a best-effort, defense-in-depth control. Its enforceability differs per OS
// and it can never defeat an external camera. See docs/SECURITY_ISOLATION.md.
//
// The generic entry point is Apply, which the desktop shell calls once the native
// window exists, passing the platform window handle. Platform-specific behaviour lives
// in the build-tagged files (screenguard_windows.go, screenguard_darwin.go, etc.).
package screenguard

// Result describes the outcome of attempting to exclude the window from capture.
type Result struct {
	// Supported is true if the current OS provides an app-controllable exclusion API.
	Supported bool
	// Applied is true if the exclusion was successfully set.
	Applied bool
	// Note is a short, non-secret human-readable explanation (e.g. why unsupported).
	Note string
}
