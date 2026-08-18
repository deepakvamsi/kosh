# Kosh — macOS Packaging Notes

## Build a .app bundle

```bash
cd cmd/localvault
wails build -platform darwin/universal   # Intel + Apple Silicon fat binary
```

Output: `build/bin/Kosh.app`

## Notarization (required for distribution outside the Mac App Store)

Without notarization macOS Gatekeeper will block the app on first run.

```bash
# 1. Sign the .app
codesign --deep --force --options runtime \
  --sign "Developer ID Application: Deepak Vamsi (TEAMID)" \
  build/bin/Kosh.app

# 2. Create a ZIP for notarisation
ditto -c -k --keepParent build/bin/Kosh.app Kosh.zip

# 3. Submit to Apple notary service (xcrun notarytool requires Xcode 13+)
xcrun notarytool submit Kosh.zip \
  --apple-id your@apple.id \
  --team-id TEAMID \
  --password "@keychain:APP_SPECIFIC_PW" \
  --wait

# 4. Staple the ticket
xcrun stapler staple build/bin/Kosh.app
```

## Privacy entitlements

The app needs NO privacy entitlements because:
- It accesses no camera, microphone, location, or contacts.
- It reads/writes only `~/Library/Application Support/Kosh/`.
- It makes no network connections.

The minimum entitlements file (`build/darwin/Kosh.entitlements`) is:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.app-sandbox</key>
  <true/>
  <key>com.apple.security.files.user-selected.read-write</key>
  <true/>
</dict>
</plist>
```

## NSWindowSharingNone (anti-screenshot)

The Wails `OnDomReady` hook calls `screenguard.Apply(0)` which on macOS is currently
a stub that returns `Applied: false` with a note to set `NSWindowSharingNone` in the
Cocoa shell. To complete this:

1. Add a small Objective-C/Swift helper (or CGO bridge) that accepts the `NSWindow*`
   pointer and calls `[window setSharingType: NSWindowSharingNone]`.
2. Call it from `domReady` after the Wails window is shown.

The vault is still safe without this step — auto-lock, masked-by-default reveal, and
clipboard auto-clear are the primary mitigations. The macOS platform API restriction
is documented in `docs/SECURITY_ISOLATION.md`.
