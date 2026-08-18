//go:build windows

package screenguard

import (
	"fmt"

	"golang.org/x/sys/windows"
)

const wdaExcludeFromCapture = 0x00000011 // WDA_EXCLUDEFROMCAPTURE (Windows 10 2004+)

// Apply calls SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) so the window is
// omitted from screenshots and most screen recorders while still visible on the
// physical display. hwnd must be the native HWND of the app window (uintptr).
func Apply(hwnd uintptr) Result {
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("SetWindowDisplayAffinity")
	r, _, err := proc.Call(hwnd, uintptr(wdaExcludeFromCapture))
	if r == 0 {
		return Result{Supported: true, Applied: false, Note: fmt.Sprintf("SetWindowDisplayAffinity failed: %v", err)}
	}
	return Result{Supported: true, Applied: true, Note: "excluded from capture (WDA_EXCLUDEFROMCAPTURE)"}
}
