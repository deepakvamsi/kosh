#requires -Version 5.1
<#
  Authenticode-sign a Kosh binary or installer (.exe / .msi) so Windows SmartScreen
  trusts it and shows a real publisher instead of "unknown publisher".

  Prerequisites:
    - signtool.exe (Windows SDK) on PATH.
    - A code-signing certificate. An OV cert works; an EV cert clears SmartScreen
      reputation immediately. Store the cert path in KOSH_SIGN_PFX and its password in
      KOSH_SIGN_PFX_PW (or adapt to a hardware token / Azure Trusted Signing).

  Usage:
    $env:KOSH_SIGN_PFX    = "C:\certs\kosh-codesign.pfx"
    $env:KOSH_SIGN_PFX_PW = "…"
    .\sign.ps1 -File ..\..\cmd\localvault\build\bin\Kosh.exe
    .\sign.ps1 -File .\Kosh-0.1.0.msi
#>
param(
  [Parameter(Mandatory)][string]$File,
  [string]$Cert      = $env:KOSH_SIGN_PFX,
  [string]$Password  = $env:KOSH_SIGN_PFX_PW,
  [string]$Timestamp = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $File))  { throw "File not found: $File" }
if (-not $Cert)              { throw "Set KOSH_SIGN_PFX to your code-signing cert (.pfx) path." }
if (-not (Get-Command signtool -ErrorAction SilentlyContinue)) {
  throw "signtool not found. Install the Windows SDK (App Certification Kit)."
}

Write-Host "Signing $File …"
signtool sign /fd SHA256 /f $Cert /p $Password /tr $Timestamp /td SHA256 $File
signtool verify /pa $File
Write-Host "Signed and verified: $File"
