# Kosh — Cross-Platform Install & Uninstall Guide

## Windows (primary platform)

### Install
```powershell
cd cmd\localvault
wails build --target windows/amd64 --nsis
# Output: build\bin\Kosh-amd64-installer.exe
```
Run the installer. It will:
- Copy `Kosh.exe` to `%ProgramFiles%\Deepak Vamsi\Kosh\`
- Create a Desktop shortcut and a Start-menu folder
- Register in **Settings → Apps → Installed apps** (fully uninstallable from there)
- Offer **"Pin to Start"** and **"Launch now"** on the final page

### Uninstall (3 ways, all fully supported)
1. **Settings → Apps → Installed Apps → Kosh → Uninstall**
2. **Control Panel → Programs → Uninstall a Program → Kosh**
3. Run `%ProgramFiles%\Deepak Vamsi\Kosh\uninstall.exe /S` (silent)

The uninstaller removes:
- The program directory
- All shortcuts (Desktop, Start Menu, pinned)
- The Add/Remove Programs registry entry
- The WebView2 data cache (`%AppData%\Kosh.exe`)
- **Does NOT delete your vault database** at `%AppData%\Kosh\vault.db` — your secrets are preserved

---

## macOS

### Install
```bash
cd cmd/localvault
wails build -platform darwin/universal
# Output: build/bin/Kosh.app
```
Drag `Kosh.app` to `/Applications`.

### Pin to Dock
```bash
defaults write com.apple.dock persistent-apps -array-add \
  '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/Applications/Kosh.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```

### Uninstall
```bash
# Remove the app
rm -rf /Applications/Kosh.app
# Remove the vault database (ONLY if you want to delete all secrets)
rm -rf ~/Library/Application\ Support/Kosh
# Remove Dock entry (drag icon off Dock normally, or)
defaults write com.apple.dock persistent-apps -array  # resets dock
```

---

## Linux

### Install (from binary)
```bash
cd cmd/localvault
GOOS=linux GOARCH=amd64 wails build
# Output: build/bin/Kosh-linux-amd64

sudo install -Dm755 build/bin/Kosh-linux-amd64 /usr/local/bin/Kosh
sudo install -Dm644 packaging/linux/localvault.desktop /usr/share/applications/localvault.desktop
```

### Pin to launcher / taskbar
Most desktop environments pick up the `.desktop` file automatically after installation. To pin manually:
- **GNOME**: Open Activities, find Kosh, right-click → "Add to Favorites"
- **KDE Plasma**: Right-click the app icon in the launcher → "Add to Task Manager"
- **Ubuntu Unity**: Click the icon while running → "Lock to Launcher"

### Uninstall
```bash
sudo rm /usr/local/bin/Kosh
sudo rm /usr/share/applications/localvault.desktop
# Optional — delete vault data
rm -rf ~/.local/share/Kosh
```

### .deb package (Ubuntu/Debian)
```bash
# After building the binary:
mkdir -p packaging/linux/deb/usr/local/bin
cp build/bin/Kosh-linux-amd64 packaging/linux/deb/usr/local/bin/Kosh
mkdir -p packaging/linux/deb/usr/share/applications
cp packaging/linux/localvault.desktop packaging/linux/deb/usr/share/applications/
dpkg-deb --build packaging/linux/deb localvault_1.0.0_amd64.deb
# Install:
sudo dpkg -i localvault_1.0.0_amd64.deb
# Uninstall:
sudo dpkg -r localvault
```
