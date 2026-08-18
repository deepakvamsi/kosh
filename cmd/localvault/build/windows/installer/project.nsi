Unicode true

####
## Kosh NSIS Installer
## Wails template values are injected from wails_tools.nsh at build time.
##
## Build:
##   cd cmd\localvault
##   wails build --target windows/amd64 --nsis
##
## Or manually (after a wails build has populated wails_tools.nsh):
##   makensis -DARG_WAILS_AMD64_BINARY=..\..\bin\Kosh.exe project.nsi
####

!include "wails_tools.nsh"

VIProductVersion "${INFO_PRODUCTVERSION}.0"
VIFileVersion    "${INFO_PRODUCTVERSION}.0"
VIAddVersionKey "CompanyName"     "${INFO_COMPANYNAME}"
VIAddVersionKey "FileDescription" "${INFO_PRODUCTNAME} Installer"
VIAddVersionKey "ProductVersion"  "${INFO_PRODUCTVERSION}"
VIAddVersionKey "FileVersion"     "${INFO_PRODUCTVERSION}"
VIAddVersionKey "LegalCopyright"  "${INFO_COPYRIGHT}"
VIAddVersionKey "ProductName"     "${INFO_PRODUCTNAME}"

ManifestDPIAware true

!include "MUI2.nsh"
!include "FileFunc.nsh"

!define MUI_ICON "..\icon.ico"
!define MUI_UNICON "..\icon.ico"
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_ABORTWARNING

# ── License agreement page behaviour ────────────────────────────────────────
# Require an explicit "I accept the terms" checkbox before Next is enabled. To
# show proprietary terms instead of Apache-2.0, point MUI_PAGE_LICENSE (below) at
# an EULA file (.txt or .rtf) — the wiring is identical.
!define MUI_LICENSEPAGE_CHECKBOX
!define MUI_LICENSEPAGE_TEXT_TOP "Please review the license terms before installing ${INFO_PRODUCTNAME}."

# ── Optional finish-page actions ──────────────────────────────────────────────
# "Launch after install" checkbox. (The Start-menu + Desktop shortcuts and the
# Add/Remove Programs entry are created by the main install section below; modern Windows
# no longer allows programmatic taskbar pinning, so we don't attempt it.)
!define MUI_FINISHPAGE_RUN         "$INSTDIR\${PRODUCT_EXECUTABLE}"
!define MUI_FINISHPAGE_RUN_TEXT    "Launch Kosh now"
!define MUI_FINISHPAGE_RUN_NOTCHECKED

# ── Installer pages ────────────────────────────────────────────────────────────
# Path is relative to this .nsi (build/windows/installer/) → repo-root LICENSE.
# To ship the proprietary agreement instead of Apache-2.0, point this at the EULA:
#   !insertmacro MUI_PAGE_LICENSE "..\..\..\..\..\EULA.txt"
# (ship exactly one — see EULA.txt for guidance.)
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\..\..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

# ── Uninstaller pages ─────────────────────────────────────────────────────────
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

Name "${INFO_PRODUCTNAME}"
OutFile "..\..\bin\${INFO_PROJECTNAME}-${ARCH}-installer.exe"

!ifdef WAILS_INSTALL_SCOPE
  !if "${WAILS_INSTALL_SCOPE}" == "user"
    InstallDir "$LOCALAPPDATA\Programs\${INFO_PRODUCTNAME}"
  !else
    InstallDir "$PROGRAMFILES64\${INFO_COMPANYNAME}\${INFO_PRODUCTNAME}"
  !endif
!else
  InstallDir "$PROGRAMFILES64\${INFO_COMPANYNAME}\${INFO_PRODUCTNAME}"
!endif

ShowInstDetails show
ShowUninstDetails show

# ── onInit: architecture check ────────────────────────────────────────────────
Function .onInit
    !insertmacro wails.checkArchitecture
FunctionEnd

# ── Main install section ───────────────────────────────────────────────────────
Section "Kosh" SEC_MAIN
    SectionIn RO          ; always installed, user cannot deselect
    !insertmacro wails.setShellContext
    !insertmacro wails.webview2runtime

    SetOutPath $INSTDIR
    !insertmacro wails.files

    # ── Shortcuts ──────────────────────────────────────────────────────────────
    CreateDirectory "$SMPROGRAMS\${INFO_PRODUCTNAME}"
    CreateShortcut  "$SMPROGRAMS\${INFO_PRODUCTNAME}\${INFO_PRODUCTNAME}.lnk" \
                    "$INSTDIR\${PRODUCT_EXECUTABLE}" "" "$INSTDIR\${PRODUCT_EXECUTABLE}" 0
    CreateShortCut  "$DESKTOP\${INFO_PRODUCTNAME}.lnk" \
                    "$INSTDIR\${PRODUCT_EXECUTABLE}" "" "$INSTDIR\${PRODUCT_EXECUTABLE}" 0

    # ── Uninstall entry in Add/Remove Programs ─────────────────────────────────
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" \
                  "DisplayName"          "${INFO_PRODUCTNAME}"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" \
                  "DisplayVersion"       "${INFO_PRODUCTVERSION}"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" \
                  "Publisher"            "${INFO_COMPANYNAME}"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" \
                  "UninstallString"      "$INSTDIR\uninstall.exe"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" \
                  "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" \
                  "DisplayIcon"          "$INSTDIR\${PRODUCT_EXECUTABLE}"
    WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" \
                  "URLInfoAbout"         "https://github.com/deepakvamsi/kosh"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" \
                  "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" \
                  "NoRepair" 1
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}" \
                  "EstimatedSize" "$0"

    !insertmacro wails.writeUninstaller
SectionEnd

# ── Uninstaller ────────────────────────────────────────────────────────────────
Section "Uninstall"
    !insertmacro wails.setShellContext

    # Remove WebView2 data cache
    RMDir /r "$AppData\${PRODUCT_EXECUTABLE}"
    # Remove program files
    RMDir /r $INSTDIR
    # Remove shortcuts
    Delete "$SMPROGRAMS\${INFO_PRODUCTNAME}\${INFO_PRODUCTNAME}.lnk"
    RMDir  "$SMPROGRAMS\${INFO_PRODUCTNAME}"
    Delete "$DESKTOP\${INFO_PRODUCTNAME}.lnk"
    Delete "$STARTMENU\Programs\${INFO_PRODUCTNAME}\${INFO_PRODUCTNAME}.lnk"
    RMDir  "$STARTMENU\Programs\${INFO_PRODUCTNAME}"

    # Remove Add/Remove Programs registry entry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INFO_COMPANYNAME}${INFO_PRODUCTNAME}"

    !insertmacro wails.unassociateFiles
    !insertmacro wails.unassociateCustomProtocols
    !insertmacro wails.deleteUninstaller
SectionEnd
