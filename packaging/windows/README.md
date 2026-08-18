# Kosh — Windows packaging

Two distribution formats, plus code-signing.

| Format | Tool | Best for |
| ------ | ---- | -------- |
| `.exe` installer (NSIS) | `wails build -nsis` | Direct user download; a friendly wizard (Welcome → License → folder → Finish). |
| `.msi` | WiX v4 (`Kosh.wxs`) | Enterprise deployment via Intune / SCCM / Group Policy; silent install. |

Both should be **Authenticode-signed** before release.

## 1. Build the app

```powershell
cd cmd\localvault
wails build -platform windows/amd64        # → build\bin\Kosh.exe
# NSIS installer in the same step:
wails build -platform windows/amd64 -nsis  # → build\bin\Kosh-amd64-installer.exe
```

## 2. Build the MSI (enterprise)

```powershell
dotnet tool install --global wix           # one-time
cd packaging\windows
.\build-msi.ps1 -Version 0.1.0             # → Kosh-0.1.0.msi
```

Silent install / uninstall:

```powershell
msiexec /i Kosh-0.1.0.msi /qn
msiexec /x Kosh-0.1.0.msi /qn
```

Keep the `UpgradeCode` GUID in `Kosh.wxs` **stable** across releases, and bump `Version`
each release so `MajorUpgrade` replaces the old install cleanly.

## 3. Sign everything (recommended: EV certificate)

```powershell
$env:KOSH_SIGN_PFX    = "C:\certs\kosh-codesign.pfx"
$env:KOSH_SIGN_PFX_PW = "…"
.\sign.ps1 -File ..\..\cmd\localvault\build\bin\Kosh.exe
.\sign.ps1 -File ..\..\cmd\localvault\build\bin\Kosh-amd64-installer.exe
.\sign.ps1 -File .\Kosh-0.1.0.msi
```

Without a signature Windows SmartScreen warns users about an "unknown publisher" — the
single biggest thing that makes an install feel untrustworthy. An OV cert signs; an EV
cert also clears SmartScreen reputation immediately. Azure Trusted Signing is a modern
alternative to a physical token.

## Notes

- **WebView2**: the Wails app needs the WebView2 runtime. It ships with current Windows
  10/11; for older images, chain the Evergreen bootstrapper or require it via your MDM.
- **License page**: the NSIS installer shows `LICENSE` (Apache-2.0) by default. To ship
  the proprietary `EULA.txt` instead, see the commented line in
  `cmd/localvault/build/windows/installer/project.nsi`. Ship exactly one.
