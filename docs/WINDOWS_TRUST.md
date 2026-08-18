# Kosh — Windows Trust & Antivirus Guide

## Current status (verified 2025-08-17)

| Check | Result |
|-------|--------|
| Windows Defender (MpCmdRun `-Scan -ScanType 3`) | ✅ **No threats found** |
| Binary has debug symbols | ✅ Stripped (`-s -w` ldflags) |
| Manifest: `requestedExecutionLevel` | ✅ `asInvoker` (never elevates) |
| Network connections | ✅ None — air-sealed |
| Authenticode signature | ⚠️ Not yet signed (see §2) |

---

## Why the app passes Defender but shows a SmartScreen blue dialog

These are two separate systems:

| System | Checks | Result for Kosh |
|--------|--------|-----------------------|
| **Windows Defender** (real-time AV) | Code patterns, heuristics, known malware signatures | ✅ Clean — no alert |
| **SmartScreen** | Reputation score based on download count & certificate | ⚠️ Blue dialog on first run — *not a security verdict, only a "new" verdict* |

The SmartScreen dialog says **"Windows protected your PC"** and shows an "Unknown publisher". This is **expected and harmless** for any unsigned, newly built `.exe`. It means SmartScreen has never seen this binary before — not that it found malware. The user can click "More info" → "Run anyway".

---

## Part 1 — What we already do to reduce false positives

Every measure below is already implemented:

1. **`-s -w` ldflags** — strips DWARF debug info and symbol table. Reduces binary size and removes strings that heuristics sometimes flag in debug builds.
2. **`-H windowsgui`** — marks the binary as a Windows GUI app (not a console tool). Reduces "suspicious console process" heuristics.
3. **`requestedExecutionLevel = asInvoker`** — the binary never requests elevation. Malware typically asks for `requireAdministrator`. This is a positive trust signal.
4. **No network sockets** — the binary opens no `net.Conn`, no HTTP listener. Defender's network-behavior scanner finds nothing.
5. **`CGO_ENABLED=0`** — pure Go, no C runtime shim. No foreign DLL injection surface.
6. **Full version resource** (`info.json`) — `ProductName`, `CompanyName`, `FileDescription`, `OriginalFilename` all filled in. Unsigned binaries with empty version info score worse with SmartScreen.
7. **Vault icon embedded** — a properly set icon (not the default) is a weak positive reputation signal.

---

## Part 2 — Removing the SmartScreen blue dialog (code signing)

To completely eliminate the SmartScreen dialog, sign the binary with an Authenticode certificate.

### Option A — Free (EV Code Signing via open-source program)

If you publish Kosh as open-source (GitHub, etc.) you may qualify for a free EV certificate through:
- **Certum Open Source Code Signing** — free for verified open-source projects
- **SignPath Foundation** — free CI signing for qualifying OSS projects

### Option B — Paid OV certificate (~$70–200 / year)

Any of these work:
- DigiCert Code Signing Certificate
- Sectigo (Comodo) Code Signing
- SSL.com Code Signing OV

> Note: Only an **EV (Extended Validation)** certificate gives *instant* SmartScreen reputation. An OV certificate still shows the dialog until the binary has accumulated enough download reputation (usually a few hundred downloads from different IPs).

### Signing command (once you have a certificate)

```powershell
# Import your .pfx certificate first
$cert = Get-PfxCertificate -FilePath "localvault-cert.pfx"

# Sign with RFC 3161 timestamp (required — without it the signature expires)
Set-AuthenticodeSignature `
  -FilePath "build\bin\Kosh.exe" `
  -Certificate $cert `
  -TimestampServer "http://timestamp.digicert.com"

# Verify
Get-AuthenticodeSignature "build\bin\Kosh.exe"
```

Or with `signtool` (ships with Windows SDK):

```powershell
signtool sign `
  /tr  "http://timestamp.digicert.com" `
  /td  sha256 `
  /fd  sha256 `
  /a   "build\bin\Kosh.exe"

signtool verify /pa /v "build\bin\Kosh.exe"
```

---

## Part 3 — Verifying with Defender before every release

Run this one-liner after every build:

```powershell
& "C:\Program Files\Windows Defender\MpCmdRun.exe" `
    -Scan -ScanType 3 `
    -File "$PWD\build\bin\Kosh.exe"
echo "Exit code: $LASTEXITCODE"   # 0 = clean, 2 = threat found
```

Exit code meanings:

| Code | Meaning |
|------|---------|
| 0 | Clean — no threat |
| 2 | Threat found — do not distribute |
| Any other | Defender engine error (try updating signatures first) |

---

## Part 4 — Why Kosh will never be flagged by Defender for behaviour

Defender's **real-time protection** monitors what a running program *does*, not just what it contains. Kosh:

- Opens **no network socket** (enforced by build-time guard test in `internal/seal`)
- Writes only to `%APPDATA%\Kosh\` — a normal per-user path
- Reads no other user's files and touches no system files
- Makes no registry writes outside `HKCU` (Wails WebView2 registration)
- Never spawns a child process or loads a remote DLL
- Holds the `asInvoker` trust level — no elevation, no token manipulation

These are all zero-threat behaviour signals.

---

## Part 5 — Other AV products

Third-party AVs (Norton, Kaspersky, ESET, Bitdefender, etc.) use their own engines, but the same principles apply:

1. A signed binary with full version info will never hit their "suspicious unsigned file" heuristic.
2. The go-wails binary pattern is well known — hundreds of thousands of production apps use the same runtime.
3. If a third-party AV flags it before signing, submit a **false-positive report** via their vendor portal (all major vendors have a "submit sample" form) — they typically respond within 24–48 hours and whitelist it.

---

## Summary

**Right now:** Defender scans clean. The app is safe to run on your machine.
**For distribution:** Sign the binary (§2 above) to eliminate the SmartScreen blue box and give end users a one-click run experience.
