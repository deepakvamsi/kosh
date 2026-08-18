# Kosh — Isolation: Network Air-Seal & Anti-Screenshot

This document states, precisely and without overstatement, what Kosh enforces
about (1) having **no network connectivity** and (2) resisting **screen capture**, and
exactly where the hard limits are on each OS. We use precise terms — no "military
grade", no absolute guarantees we cannot honor in software.

---

## Part 1 — Network air-seal (no connectivity)

### 1.1 What the app does by construction
- The Go backend imports **no HTTP/network client**, opens **no socket**, and **binds
  no port**. There is no server, no CLI, no MCP — nothing that could listen or dial.
- The Wails WebView loads **only bundled local assets** (embedded HTML/JS/CSS). It
  never fetches remote URLs, fonts, CDNs, analytics, or update endpoints.
- **Content-Security-Policy** in the app HTML is set to disallow any remote origin
  (`default-src 'self'; connect-src 'none'; img-src 'self' data:; ...`), so even if a
  dependency tried to `fetch()` a URL, the WebView refuses it.
- A **build-time guard test** (`internal/seal`) fails CI if any package in the module
  imports a forbidden networking package (`net/http`, `net` dialing, `net/rpc`, etc.),
  so the air-seal cannot regress silently. See `internal/seal/seal_test.go`.

### 1.2 The honest limit
An application **cannot fully firewall itself** — the OS, not the app, owns the network
stack. Kosh guarantees it makes no connections; it cannot guarantee that a
*compromised OS* or a co-resident malicious process won't. To make the seal external
and enforceable, apply an OS-level control (recommended):

| OS | How to hard-block the app from any network |
|----|--------------------------------------------|
| **Windows** | Add an outbound + inbound **deny** rule for the `localvault.exe` path in Windows Defender Firewall (`New-NetFirewallRule -DisplayName "Kosh deny" -Direction Outbound -Program "C:\...\localvault.exe" -Action Block`). |
| **Linux** | Run under a network-less namespace: `firejail --net=none localvault`, or `systemd-run --user -p PrivateNetwork=yes ...`, or an nftables/iptables rule matching the binary's cgroup. |
| **macOS** | Enable the App Sandbox **without** the `com.apple.security.network.client`/`.server` entitlements, and/or add a Little Snitch / PF deny rule for the app. |

These make the "air-seal" enforced by the kernel, which is the only place it can truly
be enforced.

### 1.3 Verification
- `go test ./internal/seal` proves no forbidden import exists.
- Manually: run the app with the OS firewall rule above and confirm all functionality
  (unlock, list, reveal, backup) still works — because none of it needs the network.

---

## Part 2 — Anti-screenshot / screen-capture resistance

We set the **OS window-level "exclude from capture" flag** so the vault window is
omitted from OS/screen-recording captures. This is applied on all three platforms
where an API exists, and documented where it does not.

### 2.1 Per-OS mechanism (applied at window creation, Phase 3 UI)

| OS | API | Effect |
|----|-----|--------|
| **Windows** | `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` | The window renders normally on the physical screen but appears **black/blank** in screenshots, `PrintScreen`, and most screen recorders (DWM-level exclusion, Win10 2004+). |
| **macOS** | `NSWindow.sharingType = .none` | The window is excluded from `CGWindowListCreateImage` / screen-sharing capture. |
| **Linux (X11)** | No standard exclusion API. | Best-effort only; documented as unenforceable (see 2.2). |
| **Linux (Wayland)** | Compositor mediates capture via portals; apps cannot self-exclude. | Best-effort only; documented as unenforceable. |

Because Wails owns the native window handle, the flag is applied through a small
platform shim invoked once the window exists:
- `internal/screenguard/screenguard_windows.go` → `SetWindowDisplayAffinity`.
- `internal/screenguard/screenguard_darwin.go`  → set `sharingType` on the NSWindow.
- `internal/screenguard/screenguard_linux.go`   → no-op that logs "unsupported".
- `internal/screenguard/screenguard_other.go`   → no-op fallback.

### 2.2 The honest limits (documented in THREAT_MODEL)
- **Linux** has no portable, reliable app-controlled capture-exclusion; we mark it
  best-effort and recommend not revealing secrets while screen-sharing.
- **No software can stop an external camera** pointed at the monitor.
- The exclusion applies to the app window; a secret **copied to the clipboard** and
  pasted elsewhere is outside this control (clipboard auto-clear mitigates the window).

### 2.3 Complementary controls (already in the design)
- **Reveal is momentary and per-secret**; values are masked by default.
- **Auto-lock** clears keys on inactivity.
- **Clipboard auto-clear** limits exposure after copy.
- Optionally (Phase 3) the UI can re-mask revealed fields on window blur.

---

## Summary of guarantees (precise wording)

- Kosh **makes no network connections and exposes no listener** — verified by a
  build-time guard test. For a kernel-enforced seal, apply the OS firewall/sandbox
  rule in §1.2.
- Kosh **requests OS-level exclusion of its window from screen capture** on
  Windows and macOS; on Linux this is best-effort and documented as such. No software
  can defeat an external camera.
