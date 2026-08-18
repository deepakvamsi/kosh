# Kosh — Threat Model & Security Controls

This document describes what Kosh protects against, what it does **not**, and
the concrete controls that back each claim. We deliberately avoid marketing language.
Kosh is **not** "military grade" and is **not** "SOC 2 certified". It implements
well-reviewed cryptographic primitives and a set of controls that map to common
SOC 2 Trust Services Criteria (see §7); certification is an organizational audit
process, not a property of software.

## 1. Assets

| Asset | Sensitivity |
|-------|-------------|
| Master password | Critical — never stored, derives all keys. |
| Data Encryption Key (DEK) / Key Encryption Key (KEK) | Critical — in memory only when unlocked. |
| Secret values (API keys, tokens, passwords, connection strings) | Critical. |
| Secret metadata (provider, env, alias, tags, timestamps) | Sensitive but not the secret itself. |
| Audit log | Integrity-sensitive (tamper-evident). |
| Backups | Critical (encrypted). |

## 2. Trust assumptions

- The local OS and the user account are trusted while the machine is not compromised.
- The user chooses a reasonably strong master password.
- The frontend/backend bridge is Wails' in-process binding; it is **not** a network
  socket and is not reachable by any other program.
- There is no CLI, MCP server, or AI-tool interface, so those are not part of the
  attack surface by construction.

## 3. Attackers considered (STRIDE-style)

| # | Threat | Category | Mitigation |
|---|--------|----------|------------|
| T1 | Attacker with the DB file at rest (stolen laptop, backup copy) | Info disclosure | All secrets encrypted with XChaCha20-Poly1305 under an Argon2id-derived KEK. No plaintext secrets on disk. |
| T2 | Offline brute-force of the master password | Info disclosure | Argon2id with memory-hard parameters + per-vault random salt makes guessing expensive. |
| T3 | Ciphertext tampering / bit-flipping | Tampering | AEAD (Poly1305 tag) rejects any modified ciphertext; associated data binds context. |
| T4 | Audit log tampering / deletion of evidence | Tampering / Repudiation | Append-only, hash-chained records; each entry commits to the previous hash. Verifiable chain. |
| T5 | Any external program / AI tool trying to read secrets | Elevation / Info disclosure | **No such interface exists.** No CLI, no MCP, no local server, no socket. Nothing outside the app can request a secret or a name. Secrets are revealed only inside the app UI, to the human at the keyboard. |
| T6 | Secret lingering in clipboard | Info disclosure | Clipboard auto-clear after a configurable timeout; only cleared if unchanged. |
| T7 | Secret lingering in memory | Info disclosure | Keys/plaintext held briefly, zeroized on lock and after use where the language permits. The master-password *string* is the documented exception — it crosses the Wails binding as an immutable value and cannot be scrubbed on demand (see §5). |
| T8 | Bulk export / "dump all values" | Info disclosure | There is no bulk-value-export feature or code path. Only per-secret, explicit, in-app reveal exists, and it is audited. Encrypted backups are ciphertext, not plaintext dumps. |
| T9 | Secrets leaking into logs | Info disclosure | Structured logging with an explicit "never log secret values" rule + redaction helpers. |
| T10 | Malicious backup swapped in | Tampering | Backups are authenticated (AEAD) under a vault-derived key; forged/edited archives fail to open. |
| T11 | Leftover plaintext in an imported spreadsheet | Info disclosure | Import parses the file locally, encrypts into the vault, and prompts you to delete the source `.xlsx`/`.csv`; nothing is uploaded. |
| T12 | Secret exfiltration over the network | Info disclosure | The app makes no connections and exposes no listener; enforced by the `internal/seal` build-time guard test and a `connect-src 'none'` CSP. Kernel-level enforcement via the per-OS firewall/sandbox rule in SECURITY_ISOLATION §1.2. |
| T13 | Secret captured via screenshot / screen recorder | Info disclosure | Window is excluded from OS capture on Windows (`WDA_EXCLUDEFROMCAPTURE`) and macOS (`NSWindowSharingNone`); best-effort on Linux. Masked reveal, auto-lock and clipboard auto-clear reduce the window. **Cannot defeat an external camera.** |

## 4. Out of scope (documented limitations)

- **Compromised OS / kernel / privileged malware** running as the same user while the
  vault is unlocked can read process memory. Kosh reduces the *window* (auto-lock,
  minimal plaintext lifetime) but cannot defeat root-level compromise.
- **Metadata confidentiality at rest**: with app-layer encryption, secret *values* are
  encrypted but table structure and non-secret metadata columns are visible to someone
  with the DB file. If full metadata confidentiality is required, a whole-DB encryption
  (e.g. SQLCipher) build is the alternative — see `docs/CRYPTO.md` §8.
- **Hardware side-channels**, cold-boot attacks, and **an external camera pointed at
  the screen** — no software can prevent the last one.
- **Master-password residency in memory**: the password crosses the Wails binding as an
  immutable string (see §5), so — unlike the derived keys — it cannot be explicitly
  zeroized and may linger in process memory (the WebView and Go heaps) until the garbage
  collector reclaims it. Privileged malware, a debugger, or a memory dump taken during
  that window could recover it. This is a property of the language/runtime boundary, not
  a storage choice: the password is never written to disk. It is the same class of
  exposure as the compromised-OS case above.
- **Linux screen-capture exclusion** is not reliably app-controllable (X11/Wayland);
  treated as best-effort. See `docs/SECURITY_ISOLATION.md` Part 2.
- **Kernel-enforced network isolation** must be applied by you at the OS level
  (firewall/sandbox); the app guarantees it *initiates* no traffic but cannot police
  the OS network stack itself. See `docs/SECURITY_ISOLATION.md` §1.2.

## 5. Minimizing plaintext secret lifetime

- Decrypt only on explicit in-app reveal/copy, into a short-lived buffer.
- Zeroize buffers immediately after use where feasible.
- Auto-lock zeroizes KEK/DEK on inactivity. This is enforced **in the Go backend** (a
  timer that wipes the in-memory DEK), independent of the UI, so a suspended or
  unresponsive WebView cannot keep the vault unlocked; the UI's own activity timer is a
  convenience layer on top.
- Clipboard auto-clear.
- No plaintext caching layer.
- **Master-password caveat:** the password enters Go across the Wails binding as an
  immutable `string` (`Unlock(password string)`), and the JavaScript string in the
  WebView is likewise immutable. Go's runtime cannot explicitly zero a `string`'s
  backing array, and the garbage collector may copy it. Kosh derives the KEK into
  a `[]byte` and zeroizes that and all derived key material immediately, but the
  master-password *string* itself — in both the WebView and Go heaps — persists until it
  is garbage-collected and cannot be scrubbed on demand. The password is never written
  to disk; the residual-memory exposure this creates is the limitation recorded in §4.
  Eliminating it would require passing the password across the binding as a mutable byte
  array from the WebView down, which the current Wails binding surface does not provide.

## 6. Tamper-evident audit log

Each audit record stores: `seq`, `timestamp`, `actor` (always the in-app UI session),
`action`, `target`, `outcome (allow/deny)`, `prev_hash`, and
`hash = H(prev_hash || canonical(record))`.
Any deletion or edit breaks the chain; a `VerifyChain()` routine walks the log and
reports the first inconsistency.

## 7. SOC 2 readiness mapping (readiness, not certification)

| Trust Services Criteria | How Kosh supports it |
|-------------------------|----------------------------|
| CC6.1 Logical access | Master-password gate; no external access surface at all (no CLI/MCP/network). |
| CC6.6 Encryption | Argon2id KDF + XChaCha20-Poly1305 AEAD, envelope key hierarchy, encrypted backups. |
| CC6.7 Data transmission | No off-device transmission of any kind; no network I/O. |
| CC7.2 Monitoring | Tamper-evident, hash-chained audit log with allow/deny outcomes. |
| CC7.3 / CC7.4 Incident detection & response | Health engine flags expired/old/unused/duplicate credentials for rotation. |
| CC8.1 Change management | Versioned DB schema migrations; documented crypto parameters. |
| A1.2 Availability | Encrypted local backups + restore path. |

> **Wording policy:** In UI and docs we say "implements controls that map to SOC 2
> criteria" and use precise crypto terms (Argon2id, XChaCha20-Poly1305, AEAD).
> We never say "SOC 2 certified" or "military grade".
