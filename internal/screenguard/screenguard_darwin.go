//go:build darwin

package screenguard

// Apply on macOS should set the NSWindow's sharingType to NSWindowSharingNone, which
// excludes the window from CGWindowList-based capture and screen sharing.
//
// Setting that property requires touching the Cocoa NSWindow via Objective-C (CGO),
// which is done in the Wails desktop shell (Phase 3) where the NSWindow handle is
// available, so that the pure-Go core packages stay CGO-free and cross-platform
// testable. This stub records intent; the shell performs the actual call.
//
// handle is the NSWindow pointer (as uintptr) provided by the shell.
func Apply(handle uintptr) Result {
	return Result{
		Supported: true,
		Applied:   false,
		Note:      "macOS: set NSWindow.sharingType=NSWindowSharingNone in the desktop shell",
	}
}
