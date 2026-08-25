# Changelog

All notable changes to Kosh are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries that change a security property say so explicitly, including what the property
was before — a security note that only describes the fix is not auditable.

## [Unreleased]

## [0.4.1] - 2026-08-24

### Fixed

- **A secret's description is now shown when the entry is revealed.** The description
  (non-secret metadata) was captured in the Add form and stored, but no view ever
  rendered it — it appeared nowhere in the UI. It now shows at the top of the expanded
  reveal panel when present.

## [0.4.0] - 2026-08-24

### Security

- **Argon2id cost is calibrated to the machine at vault creation, and can be raised later.**
  It was fixed at time=3 / 64 MiB / threads=4 — a floor chosen for the slowest supported
  hardware, which left every faster machine protected below its means. Since the KDF cost
  is the *only* barrier once an attacker has copied `vault.db`, that shortfall was the whole
  defence going unclaimed. Calibration targets ~750 ms per unlock, scaling memory before
  time passes, clamped to 64–512 MiB and 3–10 passes. The floor equals the old default, so
  calibration can only move a vault stronger; the ceiling avoids an unlock that swaps, which
  would page key material to disk. Settings gains a "Strengthen encryption" action
  (`Vault.RekeyKDF`) that re-wraps the DEK under stronger parameters — no secret is
  re-encrypted, existing audit MACs stay verifiable, and the recovery key keeps working. It
  requires the master password and refuses any parameter set weaker than the current one.
- **The audit log is now tamper-evident against an adversary, not only against
  corruption.** Previously the chain was `SHA-256(prev_hash ‖ record)` with no secret
  involved, so anyone able to write to `vault.db` could edit or delete a record and
  recompute every hash after it — `VerifyChain()` would then report an intact log. Records
  written while the vault is unlocked now carry an `HMAC-SHA256` under a DEK-derived
  subkey, and the chain head is anchored in `vault_meta` under the same key so tail
  truncation is detectable. Migration `0008`. Records written while the vault is *locked*
  (failed unlock, lockout) cannot be keyed — no DEK exists at that moment — and remain
  hash-chained only; this residual gap is documented in `docs/THREAT_MODEL.md`.
- **Generating a recovery key now requires re-entering the master password.** A recovery
  key is a permanent second door into the vault that survives every future password
  change, and an unattended unlocked window was previously enough to mint one.
- **Exporting a backup now requires re-entering the master password.** An export is a
  complete copy of the vault leaving the machine. `ExportBackup` takes two arguments: the
  master password authenticates the operator, the backup password seals the file.
- `ResetVault` remains deliberately ungated — its primary legitimate use is "I forgot my
  password and have no recovery key", it is destructive only, and it cannot exfiltrate
  plaintext. The reasoning is now recorded at the call site rather than implied.

### Added

- `.gitattributes`, declaring line endings explicitly (LF for source, CRLF for
  PowerShell/NSIS) so every checkout agrees.
- `SECURITY.md`: a private vulnerability-disclosure channel, response expectations, and an
  explicit scope list including the design limits that are known and accepted.
- `internal/vault.VerifyPassword`: re-authentication that does not disturb lock state and
  deliberately does not consume the unlock lockout budget (the vault is already unlocked,
  so throttling would cost availability with no security gain). Both outcomes are audited
  as `reauth`.
- Test coverage for `cmd/localvault/app.go`, the Wails binding layer, which had none: the
  nil-vault guard for every bound method, locked-vault refusal of all secret operations,
  the re-authentication gates, per-item-type round trips, and auto-lock setting fallback.
- Adversarial audit tests that simulate an attacker with database write access: full-chain
  rewrite, middle-record deletion, tail truncation, MAC stripping, forged and cleared
  anchors, and verification under the wrong key.
- Dependabot coverage for all four manifests — both Go modules, the frontend npm
  manifest, and GitHub Actions.
- Build provenance attestation on every release artifact, verifiable with
  `gh attestation verify`. `SHA256SUMS` proves a download matches what was published; it
  does not prove where the binary came from, because the same workflow generates both.
- A resolved dependency manifest (`DEPENDENCIES-*.txt`) published with each release.

### Changed

- **Licensing is now a single, unambiguous statement.** The repo shipped an Apache-2.0
  `LICENSE` *and* an `EULA.txt` while the README said "open-source" and the badge said
  "license-see below". Apache-2.0 now governs both source and official binaries; `EULA.txt`
  is removed along with the installer's alternate-licence path, and the badge says
  Apache-2.0.
- **The README competitor comparison is now factual rather than comparative.** The
  1Password/Bitwarden scorecard graded other products with ⚠️/❌ on contestable,
  point-in-time claims. It is replaced by a table of what Kosh does, each row pointing at
  the code or document that proves it, plus a plain statement of what Kosh deliberately
  does not do (team sharing, phone sync, browser autofill).
- **CI now builds and tests both Go modules on Windows, macOS and Linux.** `cmd/localvault`
  is a separate module (`replace kosh => ../../`), and `go test ./...` at the root does not
  descend into a nested module — so `app.go` and `main.go` had never been vetted, built or
  tested by CI on any platform, and neither had the platform-specific security code
  (Windows DACL hardening, screen-capture exclusion, per-OS data directories). CI also now
  runs `go build`, `tsc --noEmit`, `go test -race` where a C toolchain exists, and
  `govulncheck` against both modules.
- The Wails CLI used by release builds is pinned to `v2.14.0`, matching the `wails/v2`
  requirement in `cmd/localvault/go.mod`. It was `@latest`, which made release builds
  non-reproducible.
- Restoring a backup now clears record MACs and the audit head anchor in the same
  transaction. A restore installs the archive's key material, so the DEK — and the audit
  subkey — changes; without this, every restore would report the whole log as tampered on
  the next unlock. Audit records are preserved and downgraded to chain-only rather than
  deleted, and the restore itself is recorded as `import_backup`.

### Fixed

- **Migration idempotency is decided by schema introspection, not by matching driver
  error text.** `applyMigration` used to execute each statement and, when it failed, check
  whether the error message contained `"duplicate column name"` or `"already exists"` —
  then record the migration as applied and commit regardless. The guard depended on a
  human-readable string that is not part of any driver contract, and any other error whose
  text happened to match was silently accepted, marking a migration applied when it was
  not. `ALTER TABLE … ADD COLUMN` is now checked against `pragma_table_info` before it
  runs; every other error fails the migration and rolls it back.
- **The SQL statement splitter is a character scanner rather than a line splitter.** It
  previously cut on any line containing a semicolon, so a semicolon inside a string
  literal, a quoted identifier, or a `BEGIN … END` trigger body would split one statement
  into two fragments. It now tracks string literals (including doubled-quote escapes),
  quoted identifiers, line and block comments, and `BEGIN … END` nesting.
- **`RecoverWithKey` no longer downgrades a vault's KDF parameters.** It wrote
  `DefaultKDFParams()` back into the header, which was invisible while every vault used the
  defaults — and would have silently reset a calibrated vault to the floor on every
  recovery. It now preserves the vault's existing cost.
- **The recovery key no longer breaks when the master password is re-keyed.** The recovery
  RKEK was derived using the vault's shared `kdf_*` columns, so changing them left the
  recovery key unable to unwrap the DEK — the one credential whose entire purpose is to
  work when nothing else does. Migration `0009` gives the recovery slot its own parameter
  columns; NULL means a pre-`0009` vault and falls back to the shared values, which is what
  such a vault's RKEK was actually derived with.
- Two test files carried a UTF-8 BOM before `package`, and one struct had misaligned
  comments. CI now enforces `gofmt` on Linux, and `.gitattributes` normalises line endings
  so `gofmt -l` no longer reports CRLF working copies as findings on Windows.
- `loadMigrations` rejects two files claiming the same version instead of applying them in
  directory-listing order and recording only one.
- **A failed database read no longer presents as an empty vault.** `ListSecrets` returned a
  nil slice on error, which rendered as "you have no secrets" — the most alarming false
  statement a vault can make. It now returns `SecretListDTO{items, err}`, so
  empty-and-fine is distinguishable from could-not-read. `IsInitialized` and
  `HasRecoveryKey` likewise return `BoolQueryDTO{value, err}`: a swallowed error made the
  former offer to create a vault over one that merely failed to open, and the latter hide
  the recovery option from someone who actually had a key. The dashboard now shows "—"
  rather than 0, and the unlock screen stays put and shows the error instead of switching
  to the create-vault flow.
- The `init` audit record is written after the audit subkey is installed, so the first
  entry in every new vault's log is authenticated like every later one.
- The `autolock` audit record is written before `Lock()` zeroizes the key, so it is
  authenticated. Previously it was written after and could not be.

---

Releases up to and including `v0.3.0` predate this changelog; see the git history and
release notes for those.
