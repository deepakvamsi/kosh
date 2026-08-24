# Kosh — Cryptographic Design

All primitives come from well-reviewed libraries:
`golang.org/x/crypto/argon2`, `golang.org/x/crypto/chacha20poly1305`, and
`crypto/rand`. No custom cipher construction. We use **precise** terminology and make
no "military grade" claims.

## 1. Primitives

| Purpose | Primitive | Parameters |
|---------|-----------|------------|
| Password-based key derivation | **Argon2id** | Calibrated at vault creation to ~750 ms on that machine, within time=3–10 and memory=64–512 MiB (threads=4). Stored per-vault in the header and raisable later without re-encrypting anything. 16-byte random salt, 32-byte output. |
| Authenticated encryption | **XChaCha20-Poly1305** | 32-byte key, 24-byte random nonce, 16-byte tag |
| Randomness | `crypto/rand` | salts, nonces, DEK, recovery key |
| Integrity of audit log | SHA-256 hash chain | see THREAT_MODEL §6 |
| Constant-time compare | `crypto/subtle` | header/tag verification helpers |

XChaCha20 is chosen for its **24-byte random nonce**, which makes nonce reuse
practically impossible with `crypto/rand` — important because we encrypt many small
records.

## 2. Envelope key hierarchy

```
Master Password ──Argon2id(salt, params)──▶  KEK (Key Encryption Key, 32 B, memory only)
                                               │
                                               │ XChaCha20-Poly1305 wrap
                                               ▼
                               Wrapped DEK  (stored in DB, vault_meta)
                                               │ unwrap on unlock
                                               ▼
                                     DEK (Data Encryption Key, 32 B, memory only)
                                               │ XChaCha20-Poly1305
                                               ▼
                          Each secret value: nonce || ciphertext || tag  (stored per row)
```

Why envelope encryption:
- **Password change / rotation** re-wraps the *same* DEK under a new KEK — no need to
  re-encrypt every secret.
- **Recovery key** is a second independent wrap of the same DEK (see §5).
- The DEK never touches disk in plaintext; the KEK is never persisted at all.

## 3. Vault header (`vault_meta`, single row)

```
kdf            = "argon2id"
kdf_time       = 3
kdf_memory_kib = 65536
kdf_threads    = 4
kdf_salt       = 16 random bytes
verifier       = XChaCha20Poly1305(KEK, nonce, "LOCALVAULT-VERIFY")   -- to check password without exposing DEK
dek_wrapped    = nonce || XChaCha20Poly1305(KEK, dek)                  -- password-wrapped DEK
dek_recovery   = nonce || XChaCha20Poly1305(RKEK, dek)   (nullable)   -- recovery-key-wrapped DEK
schema_version = 1
created_at, updated_at
```

The **verifier** lets us confirm a typed password is correct (the AEAD tag validates)
before attempting to unwrap the DEK, and without ever storing the password or the DEK.

## 4. Per-secret encryption

For each secret value `P`:
```
nonce  = 24 random bytes
AD     = canonical associated data = secret_id || provider || environment   (binds context)
C      = XChaCha20Poly1305.Seal(DEK, nonce, P, AD)
stored = nonce || C     (in secrets.value_enc, BLOB)
```
Binding provider/environment as associated data means a ciphertext copied from a DEV
row cannot be silently presented as a PROD row without failing authentication.

## 5. Recovery key (second unlock path)

On first init we optionally generate a 256-bit **recovery key**, shown to the user
**once**, encoded as grouped Base32. From it we derive `RKEK` (Argon2id with a separate
salt) and store a second wrap `dek_recovery`. If the master password is lost, the
recovery key unwraps the DEK and lets the user set a new password. The recovery key
itself is never stored in plaintext.

## 6. Backups

An encrypted backup is a self-contained authenticated archive:
```
header { format_version, kdf_params, salt }   -- plaintext, non-secret
body   = XChaCha20Poly1305(BK, nonce, serialized_vault, AD=header)
```
`BK` (backup key) is derived from the master password (or recovery key) via Argon2id
with the backup salt. A tampered archive fails the AEAD tag and will not restore.

## 7. Memory hygiene

- KEK/DEK stored in byte slices that are explicitly zeroized (`crypto.Zero`) on lock.
- Plaintext secret buffers are zeroized right after reveal/copy/inject.
- Go's GC can copy memory, so this is best-effort defense-in-depth, documented as such
  in THREAT_MODEL §4.

## 8. Alternative: whole-DB encryption

The default build uses **app-layer** encryption (pure-Go `modernc.org/sqlite`, no CGO)
which encrypts secret *values* but leaves table structure/metadata readable in the file.
For deployments needing metadata confidentiality at rest, a SQLCipher build (CGO)
encrypts the entire file. This is a build-time choice; the `crypto`/`vault` APIs are
identical either way. Trade-offs are documented in THREAT_MODEL §4.

## 9. Parameter tuning

Argon2id parameters are stored in the vault header so they can be increased over time.

**Calibration.** A fixed cost has to be chosen for the slowest machine anyone might run
Kosh on, which leaves every faster machine protected below its means. Because the only
barrier against an attacker who has copied `vault.db` is the KDF cost, that shortfall is
the whole defence going unclaimed. `crypto.CalibrateKDFParams` therefore measures Argon2id
on the machine creating the vault and picks the strongest parameters that still complete
within roughly 750 ms.

Memory is scaled before time passes, because memory hardness is what erodes an attacker's
GPU and ASIC advantage. The result is clamped to `[64 MiB, 512 MiB]` and `[3, 10]`
passes:

* the **floor equals the historical default**, so calibration can only ever move a vault
  stronger — a slow or noisy measurement cannot negotiate protection downward;
* the **ceiling** exists because the cost is paid on every unlock, on the user's own
  machine. Past ~512 MiB an unlock risks swapping, which is both slow and a route for key
  material to reach the page file.

**Raising the cost later.** `Vault.RekeyKDF` derives a new KEK under stronger parameters
and re-wraps the DEK. The DEK itself never changes, so:

* no secret is re-encrypted — there is nothing to re-encrypt incorrectly;
* the audit MAC subkey is unchanged, so every existing audit record stays verifiable;
* the recovery key keeps working, because it carries its own KDF parameters
  (migration `0009`) rather than borrowing the master password's.

Re-keying requires the master password, not merely an unlocked vault, and refuses any
parameter set weaker than the current one in either dimension.
On unlock, if stored params are below the current recommended floor, the UI can prompt
a transparent re-derivation (rewrap DEK) to upgrade security without re-encrypting data.
