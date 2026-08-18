#requires -Version 5.1
<#
  Build the Kosh MSI with WiX v4.

  Prerequisites (one-time):
    dotnet tool install --global wix

  Usage:
    .\build-msi.ps1                       # uses defaults below
    .\build-msi.ps1 -Version 0.2.0 -Exe ..\..\cmd\localvault\build\bin\Kosh.exe
#>
param(
  [string]$Exe     = "..\..\cmd\localvault\build\bin\Kosh.exe",
  [string]$Version = "0.1.0",
  [string]$Out     = "Kosh-$Version.msi"
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path $Exe)) {
  throw "Executable not found: $Exe  (build it first: cd cmd/localvault && wails build)"
}
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  throw "WiX not found. Install it: dotnet tool install --global wix"
}

Write-Host "Building $Out from $Exe (v$Version)…"
wix build .\Kosh.wxs -d ExeSource=$Exe -d Version=$Version -o $Out
Write-Host "Done: $Out"
Write-Host "Sign it next:  .\sign.ps1 -File $Out"
