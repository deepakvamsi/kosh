# Dependencies & transparency

Kosh is built entirely from open-source components. This file lists them, what each is
used for, and where to verify it. **None of these libraries perform network I/O in Kosh's
usage** — the air-seal is enforced by a build-time test (`internal/seal`) that fails CI if
any first-party package imports a networking package.

License identifiers below are best-effort; the authoritative terms live in each project's
repository, in `go.sum` (Go), and in `cmd/localvault/frontend/package-lock.json` (npm).

---

## Backend — Go (direct dependencies)

| Package | Purpose in Kosh | License | Source |
|---------|-----------------|---------|--------|
| `golang.org/x/crypto` | Argon2id KDF, XChaCha20-Poly1305 AEAD, BLAKE2b keyed hash | BSD-3-Clause | https://pkg.go.dev/golang.org/x/crypto |
| `golang.org/x/sys` | OS syscalls: Windows DACL hardening, screen-capture exclusion | BSD-3-Clause | https://pkg.go.dev/golang.org/x/sys |
| `modernc.org/sqlite` | Pure-Go SQLite driver (no CGO) — the encrypted vault store | BSD-3-Clause | https://gitlab.com/cznic/sqlite |
| `github.com/xuri/excelize/v2` | Parse `.xlsx` files during one-time import | BSD-3-Clause | https://github.com/qax-os/excelize |
| `github.com/wailsapp/wails/v2` | Native desktop shell (Go backend ↔ system webview) | MIT | https://github.com/wailsapp/wails |

## Frontend — npm (direct dependencies)

| Package | Purpose in Kosh | License | Source |
|---------|-----------------|---------|--------|
| `react`, `react-dom` | UI runtime | MIT | https://react.dev |
| `vite`, `@vitejs/plugin-react` | Build tool / bundler | MIT | https://vitejs.dev |
| `typescript` | Language + type checker | Apache-2.0 | https://www.typescriptlang.org |
| `tailwindcss`, `@tailwindcss/vite` | Styling | MIT | https://tailwindcss.com |
| `lucide-react` | Icon set | ISC | https://lucide.dev |
| `clsx` | className composition | MIT | https://github.com/lukeed/clsx |
| `class-variance-authority` | Variant-based styling | Apache-2.0 | https://github.com/joe-bell/cva |
| `tailwind-merge` | Merge/dedupe Tailwind classes | MIT | https://github.com/dcastil/tailwind-merge |
| `@types/react`, `@types/react-dom` | Type definitions (dev only) | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped |

## Notable transitive dependencies

Pulled in by the above (not used directly). Full lists: `go.sum` and `package-lock.json`.

| Package | Via | License |
|---------|-----|---------|
| `github.com/labstack/echo/v4` | Wails (internal asset server) | MIT |
| `github.com/gorilla/websocket` | Wails (dev-mode bridge) | BSD-2-Clause |
| `github.com/google/uuid` | Wails | BSD-3-Clause |
| `github.com/hashicorp/golang-lru/v2` | modernc/sqlite | MPL-2.0 |
| `github.com/richardlehane/mscfb`, `msoleps` | excelize | Apache-2.0 |
| `golang.org/x/net`, `golang.org/x/text` | transitive | BSD-3-Clause |

> `hashicorp/golang-lru` is MPL-2.0 (weak copyleft, file-level). It is used unmodified as a
> library, which MPL-2.0 permits without affecting Kosh's own licensing.

---

## Regenerate a complete, authoritative report

**Go** — every module and its license:
```bash
go install github.com/google/go-licenses@latest
go-licenses report ./...            # from the repo root and from cmd/localvault
go list -m all                      # full module graph
```

**npm** — every package and its license:
```bash
cd cmd/localvault/frontend
npx license-checker --summary       # counts by license
npx license-checker --json          # full detail
```

## Integrity

- Go module checksums are pinned and verifiable: `go mod verify` (both modules).
- npm packages are pinned with integrity hashes in `package-lock.json`; `npm ci` verifies
  them against the registry on every install.
