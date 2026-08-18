# Kosh — Architecture (revised: app-only, local-only)

> Kosh is a **strictly local, offline, single desktop application** for managing
> your developer secrets / API keys / passwords. It has:
>
> - **NO cloud backend, NO login server, NO telemetry, NO analytics, NO network calls**
>   for its core function.
> - **NO CLI** — everything happens inside the app.
> - **NO MCP server** — nothing ever listens on a network port.
> - **NO AI tool access of any kind** — no AI agent (Claude Code, Cursor, Codex,
>   Gemini, etc.) can read your secrets, and none can even list their names. There is
>   no interface for them to connect to. Secrets live only inside this app and are
>   revealed only to you, on screen, when you ask.
>
> The vault is one process reading and writing one encrypted database file on your own
> machine. Because it is written in Go + Wails, the **same code builds on Windows,
> Linux, and macOS**.

## 1. High-level component map

```
┌───────────────────────────────────────────────────────────────────────┐
│                    Kosh  (single desktop process)                 │
│                                                                         │
│  ┌───────────────────────────┐        ┌──────────────────────────────┐ │
│  │   Frontend (WebView)      │  Wails │        Go backend             │ │
│  │  React + TS + Tailwind    │◀──────▶│   (bound methods, in-process, │ │
│  │  + shadcn/ui              │  bind  │    NO HTTP, NO socket)        │ │
│  │                           │        │                               │ │
│  │  - Dashboard              │        │  ┌─────────────────────────┐  │ │
│  │  - Secrets                │        │  │ app  (Wails bindings)   │  │ │
│  │  - Providers              │        │  ├─────────────────────────┤  │ │
│  │  - Token Health           │        │  │ vault (domain core)     │  │ │
│  │  - Import (Excel/CSV)     │        │  ├─────────────────────────┤  │ │
│  │  - Audit                  │        │  │ crypto (KDF + AEAD)     │  │ │
│  │  - Backups                │        │  ├─────────────────────────┤  │ │
│  │  - Settings               │        │  │ storage (SQLite)        │  │ │
│  │                           │        │  ├─────────────────────────┤  │ │
│  │                           │        │  │ audit / health / backup │  │ │
│  └───────────────────────────┘        │  │ import (xlsx/csv)       │  │ │
│                                        │  └─────────────────────────┘  │ │
│                                        └──────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
        Encrypted SQLite DB   +   Encrypted local backups
        Windows: %APPDATA%\Kosh\vault.db
        Linux:   ~/.local/share/Kosh/vault.db  (XDG_DATA_HOME)
        macOS:   ~/Library/Application Support/Kosh/vault.db
```

There is exactly **one** executable. No companion CLI, no background server, no helper
that other programs can talk to. The frontend and backend communicate over Wails'
**in-process binding** (a function call bridge), which is **not** a TCP/HTTP endpoint —
nothing outside the app can reach it.

## 2. What talks to what (trust boundaries)

| Boundary | Description | Notes |
|----------|-------------|-------|
| You → app UI | You type the master password and click reveal/copy. | Password held in memory only long enough to derive keys; never persisted. |
| Frontend ⇄ Backend | Wails in-process bindings. | Not a network socket. Only *you*, driving the UI, cause a reveal. |
| Backend ⇄ Disk | Encrypted SQLite via `storage`. | Only ciphertext + non-secret metadata written. |
| App → Clipboard | On explicit copy only. | Auto-cleared after a timeout. |
| Import file → app | You pick an `.xlsx`/`.csv`; it is parsed locally, encrypted, then you delete the source. | The source spreadsheet is never uploaded anywhere. |
| Backup file ← app | Encrypted archive you save locally. | Restorable only with your master password / recovery key. |

There is **no boundary to any AI tool, any network service, or any other process.**
That interface simply does not exist.

## 3. "What passwords do I have?" — names vs. values

A core idea you asked for: the app can always show you the **list of secret names /
aliases** (e.g. `OPENAI_DEV`, `AWS_PROD`, `GITHUB_DEV`) — that is cheap and needs no
decryption of values. The **actual secret value** is decrypted only when *you* click
reveal or copy, one at a time, and every such action is written to the audit log.

- **Listing names**: always available while unlocked; no value is decrypted.
- **Revealing a value**: explicit, per-secret, audited, short-lived in memory.
- **Bulk dump of all values**: there is no feature and no caller that does this.

## 4. Go package responsibilities

- **`internal/crypto`** — Argon2id KDF, XChaCha20-Poly1305 AEAD, envelope key
  wrap/unwrap, secure random, zeroization, constant-time compare.
- **`internal/storage`** — SQLite (`modernc.org/sqlite`, pure Go / no CGO), schema +
  migrations, ciphertext CRUD, per-OS data directory, file-permission hardening.
- **`internal/vault`** — Domain core: init/unlock/lock, auto-lock, secret CRUD, alias
  resolution, environments, tags/folders. **Listing names never decrypts values.**
- **`internal/audit`** — Append-only, hash-chained (tamper-evident) audit log.
- **`internal/health`** — Token health/scoring; expired/unused/old/duplicate detection.
- **`internal/backup`** — Encrypted export/import of the vault.
- **`internal/import`** — One-time importer for your existing Excel/CSV sheets.
- **`cmd/localvault`** — The single Wails desktop entry point.

*(Removed from the earlier draft: `cmd/keyvault` CLI, `cmd/keyvault-mcp` MCP server,
and `internal/appperm` per-application permissions — none are needed for an app-only,
no-external-access design.)*

## 5. Data at rest

- Single SQLite file per the per-OS path above (plus `-wal` / `-shm`).
- **Envelope encryption:** a random Data Encryption Key (DEK) encrypts every secret
  value; the DEK is wrapped by a Key Encryption Key (KEK) derived from your master
  password via Argon2id. See `docs/CRYPTO.md`.
- Metadata (provider, environment, alias, tags, timestamps) is stored so the app can
  show names, search, and compute health. Secret *values* are always ciphertext.
- File/dir permissions are tightened to your OS user (owner-only on Linux/macOS via
  `0600`; owner+SYSTEM DACL on Windows).

## 6. Data in motion

**None.** No network I/O for any core operation on any platform. The only files that
ever leave the app are backups and exports *you* explicitly create and place yourself.

This is enforced as a design invariant, not a setting:
- The Go backend imports no HTTP/network client, opens no socket, binds no port.
- The WebView loads only bundled local assets and sets a Content-Security-Policy that
  forbids any remote origin (`connect-src 'none'`).
- A build-time guard test (`internal/seal`) fails CI if any first-party package imports
  a forbidden networking package, so the air-seal cannot regress silently.
- Because an app cannot fully firewall itself, `docs/SECURITY_ISOLATION.md` §1.2 gives
  the per-OS firewall/sandbox rule to make the seal kernel-enforced.

## 6a. Anti-screenshot (screen-capture resistance)

At window creation the desktop shell calls `internal/screenguard.Apply` to request
OS-level exclusion of the vault window from screen capture:
- **Windows:** `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`.
- **macOS:** `NSWindow.sharingType = NSWindowSharingNone`.
- **Linux:** no portable API exists (X11/Wayland); best-effort, documented as such.

This is defense-in-depth and cannot defeat an external camera. Full details and the
honest limits are in `docs/SECURITY_ISOLATION.md` Part 2.

## 7. Runtime states

```
        first run                unlock (Argon2id)             idle timeout
Uninitialized ───▶ Initialized ───────────────▶ Unlocked ───────────────▶ Locked
                                    ▲                                        │
                                    └───────────────── unlock ──────────────┘
```

## 8. Cross-platform notes

- **Windows**: primary target; DACL hardening in `permissions_windows.go`.
- **Linux / macOS**: same Go code; `permissions_other.go` uses `0600`; Wails builds a
  native window using the platform WebView (WebKitGTK on Linux, WKWebView on macOS).
- The `crypto`, `storage`, `vault`, and `audit` packages are 100% portable Go with no
  CGO, so `go test ./...` runs identically on all three.

## 9. Non-goals (explicit)

- No syncing, sharing, multi-user, or server of any kind.
- No CLI, no MCP, no AI-tool integration, no plugin that can read secrets.
- No sending any secret or metadata off the device.
