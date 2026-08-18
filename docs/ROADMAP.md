# Kosh — Roadmap (revised: app-only, local-only, cross-platform)

Built incrementally. After **each** phase we run `go test ./...` and `go vet ./...`.
Nothing here introduces a cloud backend, login server, telemetry, CLI, MCP server, or
any AI-tool interface. Kosh is one desktop app that talks to one encrypted local
database. Because it is Go + Wails, the same code targets **Windows, Linux, macOS**.

## Phase 1 — Foundations (crypto + storage + vault core)  ✅ DONE
- [x] Design docs: architecture, threat model, crypto design, DB schema, roadmap.
- [x] Go module + directory layout.
- [x] `internal/crypto`: Argon2id KDF, XChaCha20-Poly1305 AEAD, envelope wrap/unwrap,
      secure random, zeroization, constant-time compare. **Unit tested.**
- [x] `internal/storage`: SQLite (modernc.org/sqlite, no CGO), schema + migrations,
      provider seed, ciphertext CRUD, file-permission hardening. **Unit tested.**
- [x] `internal/vault`: init / unlock / lock, auto-lock, secret CRUD, alias resolution,
      environments. **Unit tested.**
- [x] `internal/audit`: hash-chained append + `VerifyChain`. **Unit tested.**
- [x] `go test ./...` + `go vet ./...` green.

## Phase 2 — Health, backups, tags/folders  ✅ DONE
- [x] Token health / security score; detect expired / unused / old / duplicate.
- [x] Expiration & rotation tracking.
- [x] Tags & folders CRUD; "list names" queries that never decrypt values.
- [x] Encrypted local backups (export/import) with restore.
- [x] Cross-platform data directory resolution (Windows/Linux/macOS).

## Phase 3 — Desktop UI (Wails + React + TS + Tailwind)  ✅ DONE
- [x] First-run setup + unlock screen with app branding.
- [x] Views: Dashboard, Secrets, Providers, Token Health, Audit, Backups, Settings.
- [x] Reveal/copy with auto-mask (30 s) + clipboard auto-clear (30 s).
- [x] Anti-screenshot: `WDA_EXCLUDEFROMCAPTURE` on Windows, `NSWindowSharingNone` on macOS.
- [x] Air-seal: `connect-src 'none'` CSP, no CDN, no remote fetch.

## Phase 4 — Excel / CSV import  ✅ DONE
- [x] `internal/importer`: read `.xlsx`/`.csv`, auto-detect columns, preview, encrypt into vault.
- [x] Alias sanitisation, provider + env normalisation, expiry parsing.
- [x] "Delete your source file" reminder after successful import.

## Phase 5 — Hardening & packaging  ✅ DONE
- [x] Auto-lock timer wired to the `autolock_seconds` setting (default 5 min).
- [x] On-lock state cleared from all open views (revealed values wiped from memory).
- [x] Audit-chain verifier widget with full details + re-verify button.
- [x] Windows installer: NSIS script, app icon, version info, code-signing guidance.
- [x] Linux packaging: AppImage + `.deb` build script.
- [x] macOS `.app` bundle notes.
- [x] `docs/SOC2_READINESS.md` — full checklist walkthrough.
- [x] `go test ./...` + `go vet ./...` + `tsc --noEmit` + `go build` all green.

## Removed from the original brief (per your decision)
- ❌ Secure CLI (`keyvault get` / `keyvault run`) — not needed; app-only.
- ❌ MCP server — removed entirely; nothing listens on any port.
- ❌ AI-agent integration & per-application permissions — no external program or AI
  tool can read secrets or even list names. That interface does not exist.
- ❌ Code Review Graph adapter — depended on the external-access model we dropped.

## Testing policy
- Unit tests for all crypto and storage logic (round-trip, tamper-rejection,
  wrong-password, chain-verification, import mapping).
- `go vet ./...` must pass with no findings after every phase.
- Portable packages must pass `go test ./...` on Windows, Linux and macOS.
