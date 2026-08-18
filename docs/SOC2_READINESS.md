# Kosh — SOC 2 Readiness Checklist

> **Status: readiness review, not certification.**
> SOC 2 certification is an organisational audit process performed by an independent
> CPA firm. This document maps Kosh's implemented controls to the AICPA Trust
> Services Criteria (TSC) to demonstrate readiness for that audit. We do not claim
> "SOC 2 certified" status and we never use the phrase "military grade".

---

## CC1 — Control Environment

| Criterion | Control | Status |
|-----------|---------|--------|
| CC1.1 Commitment to competence | Engineering practices: typed Go, TypeScript strict mode, `go vet`, unit tests for every security-critical package. | ✅ |
| CC1.2 Board oversight | N/A (single-user desktop tool; no board). | N/A |
| CC1.3 Policies communicated | `docs/SECURITY_ISOLATION.md`, `docs/THREAT_MODEL.md`, and this document. | ✅ |

---

## CC6 — Logical and Physical Access

| Criterion | Control | Status |
|-----------|---------|--------|
| **CC6.1** Logical access controls | Master-password gate (Argon2id KDF). No access without the password — not even the developer can bypass this. | ✅ |
| **CC6.1** No external access surface | No CLI, no MCP server, no AI-tool interface, no network socket. The attack surface is exactly one: the master password. | ✅ |
| **CC6.2** Identification / authentication | User is identified by knowledge of the master password. No shared credentials; each vault is single-user. | ✅ |
| **CC6.3** Access removal | `Lock()` zeroizes the in-memory DEK/KEK immediately. Auto-lock fires after configurable idle timeout (default 5 min). | ✅ |
| **CC6.6** Encryption at rest | XChaCha20-Poly1305 AEAD per-secret with envelope key hierarchy. Argon2id with memory-hard parameters. See `docs/CRYPTO.md`. | ✅ |
| **CC6.7** Data transmission security | No data is transmitted. `connect-src 'none'` CSP. Build-time guard test fails if any first-party package imports `net/http`. | ✅ |
| **CC6.8** Malware prevention | App imports no network package; no auto-update mechanism that could deliver modified code; no remote execution path. | ✅ |

---

## CC7 — System Operations

| Criterion | Control | Status |
|-----------|---------|--------|
| **CC7.1** Detection of security events | Every reveal, copy, create, update, delete, lock, unlock, and backup event is written to the tamper-evident audit log. | ✅ |
| **CC7.2** Monitoring | Hash-chained `audit_log` table; `VerifyChain()` in Go + "Verify chain" button in the Audit UI. Any deletion or modification breaks the chain and is immediately visible. | ✅ |
| **CC7.3** Incident evaluation | Audit UI flags broken chain with a red banner and actionable guidance ("do not trust entries at or after seq N"). | ✅ |
| **CC7.4** Incident response | User is directed to export an encrypted backup before further use; backup is authenticated (AEAD) so a forged backup fails to restore. | ✅ |
| **CC7.5** Remediation | Token Health view surfaces expired, unused, old, and duplicate credentials and prompts rotation. | ✅ |

---

## CC8 — Change Management

| Criterion | Control | Status |
|-----------|---------|--------|
| **CC8.1** Authorised changes only | Versioned Go module with dependency pinning (`go.sum`). All crypto parameter choices documented in `docs/CRYPTO.md` with rationale. DB schema changes go through numbered migrations. | ✅ |

---

## A1 — Availability

| Criterion | Control | Status |
|-----------|---------|--------|
| **A1.2** Backup and recovery | Encrypted backup export (XChaCha20-Poly1305 under a fresh Argon2id-derived key). Authenticated restore: wrong password or tampered archive → `ErrBadBackup`. | ✅ |
| **A1.3** Recovery testing | Backup round-trip test in `internal/backup/backup_test.go` covers correct restore, wrong-password rejection, and tamper rejection. | ✅ |

---

## PI1 — Processing Integrity

| Criterion | Control | Status |
|-----------|---------|--------|
| **PI1.1** Complete and accurate processing | AEAD tag rejects any bit-flipped or truncated ciphertext. Associated data (row ID + provider + environment) is bound to each ciphertext — swapping blobs between rows fails authentication. | ✅ |
| **PI1.2** System processing commitments | All inputs are validated before storage (alias sanitisation, environment enum, provider FK). | ✅ |

---

## C1 — Confidentiality

| Criterion | Control | Status |
|-----------|---------|--------|
| **C1.1** Identification of confidential information | Secret *values* are always ciphertext on disk. Metadata (alias, provider, env, timestamps) is stored in clear but contains no secrets. | ✅ |
| **C1.2** Disposal of confidential information | In-memory: DEK/KEK zeroized on lock. Clipboard: auto-cleared after 30 s. Import: user reminded to delete source spreadsheet. | ✅ |

---

## P — Privacy

Kosh collects no personal data beyond what the user deliberately stores.
There is no telemetry, analytics, crash reporting, or any outbound data channel.
GDPR / CCPA obligations for Kosh's own operation: **none** (no data leaves the device).

---

## Gaps and documented limitations

| Gap | Why accepted / mitigation |
|-----|---------------------------|
| Compromised OS / kernel | Cannot be mitigated in software. Auto-lock minimises the window. |
| Linux screenshot exclusion | No portable API; documented as best-effort; mitigated by masked reveal + auto-lock. |
| External camera | No software defence. Mitigated by auto-mask (30 s) and auto-lock. |
| Metadata confidentiality at rest | SQLite metadata is in clear (see `docs/THREAT_MODEL.md` §4). Mitigated by file ACLs. Full-DB encryption (SQLCipher) is a future option. |
| Code-signing / binary integrity | Not yet automated. See `packaging/*/INSTALLER_NOTES.txt` and `MACOS_NOTES.md` for signing guidance. |

---

## Wording policy reminder

When describing security properties in marketing, documentation, or UI copy, use:
- ✅ "Argon2id key derivation with memory-hard parameters"
- ✅ "XChaCha20-Poly1305 authenticated encryption"
- ✅ "implements controls that map to SOC 2 Trust Services Criteria"
- ❌ Never: "military grade", "bank-grade", "SOC 2 certified", "unbreakable"
