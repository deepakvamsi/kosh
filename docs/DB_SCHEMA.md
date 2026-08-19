# Kosh — Database Schema (current)

Pure-Go SQLite (`modernc.org/sqlite`, no CGO). Secret values always stored as AEAD ciphertext (`nonce || ciphertext || tag`). No plaintext secret ever written.

## Migration framework

Migrations live in `internal/storage/migrations/` as ordered `NNNN_name.sql` files, embedded into the binary at compile time with `//go:embed`. Applied automatically on every `Open()` in ascending numeric order.

**Key properties:**
- Each migration runs in its own transaction.
- `ALTER TABLE … ADD COLUMN` errors with "duplicate column name" are silently ignored — so every migration is safe against a partially-upgraded database.
- `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS` are used for all idempotent DDL.
- `schema_migrations(version, applied_at)` tracks which migrations have been applied.
- Migration `0005_schema_solidify` is the catch-all guard: it re-adds every column from 0002–0004 so any `vault.db` created from a pre-solidification binary is automatically upgraded on the next launch.

**Applied migrations:**

| Version | File | What it adds |
|---------|------|-------------|
| 1 | `0001_init.sql` | All core tables: `vault_meta`, `providers`, `folders`, `secrets`, `tags`, `secret_tags`, `audit_log`, `settings` |
| 2 | `0002_custom_fields.sql` | `secrets.custom_fields TEXT DEFAULT '{}'` |
| 3 | `0003_item_type.sql` | `secrets.item_type TEXT DEFAULT 'api_key' CHECK (…)` |
| 4 | `0004_totp_favorites_history.sql` | `secrets.is_favorite`, `secrets.totp_enc`, `secret_history` table |
| 5 | `0005_schema_solidify.sql` | Idempotent guards — re-adds all 0002–0004 columns if missing |
| 6 | `0006_drop_secret_history.sql` | Removes the `secret_history` table — value-history feature dropped; purges retained previous values on upgrade |
| 7 | `0007_keypair_item_type.sql` | Rebuilds `secrets` to widen the `item_type` CHECK to include `keypair` (access-key/secret-key pair as one entry); FK-safe, ciphertext copied verbatim |

---

## Tables

### `vault_meta` (single row, id=1)

Stores the vault's key material. No plaintext master password is ever stored.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Always 1 |
| `kdf` | TEXT | Algorithm name, always `"argon2id"` |
| `kdf_time` | INTEGER | Argon2id time cost |
| `kdf_memory_kib` | INTEGER | Argon2id memory cost in KiB |
| `kdf_threads` | INTEGER | Argon2id parallelism |
| `kdf_salt` | BLOB | 16-byte random per-vault salt |
| `verifier` | BLOB | Proof token used to check the master password without exposing the DEK |
| `dek_wrapped` | BLOB | DEK encrypted under the KEK (Argon2id of master password) |
| `recovery_salt` | BLOB | Nullable; present only if recovery key was generated |
| `dek_recovery` | BLOB | Nullable; DEK wrapped under the recovery KEK |
| `schema_version` | INTEGER | Legacy field (schema is now tracked in `schema_migrations`) |
| `created_at` | INTEGER | Unix timestamp |
| `updated_at` | INTEGER | Unix timestamp |

---

### `providers`

Built-in and custom providers (AWS, OpenAI, GitHub, …). Seeded idempotently on every `Open()`.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `key` | TEXT UNIQUE | Short identifier, e.g. `aws`, `openai` |
| `name` | TEXT | Display name |
| `category` | TEXT | `cloud` / `ai` / `vcs` / `platform` / `db` / `custom` |
| `is_builtin` | INTEGER | 1 = shipped with Kosh, 0 = user-added |
| `created_at` | INTEGER | Unix timestamp |

**Built-in providers:** aws, gcp, azure, openai, anthropic, gemini, xai, mistral, groq, deepseek, openrouter, github, gitlab, bitbucket, cursor, replit, vercel, cloudflare, docker, postgresql, mongodb, redis, custom

---

### `folders`

Optional hierarchical folders for organising secrets.

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK AUTOINCREMENT | |
| `name` | TEXT | Folder display name |
| `parent_id` | INTEGER FK → `folders(id)` ON DELETE CASCADE | Nullable; enables nesting |
| `created_at` | INTEGER | Unix timestamp |

UNIQUE constraint: `(parent_id, name)`

---

### `secrets` — core table

Every row holds one vault item. **`value_enc` is always ciphertext. No row ever holds a plaintext secret.**

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK AUTOINCREMENT | Used as associated data in AEAD — ciphertext is bound to this row |
| `alias` | TEXT UNIQUE | Human name, e.g. `OPENAI_PROD` |
| `item_type` | TEXT DEFAULT `'api_key'` | `api_key` / `login` / `secure_note` / `keypair` (value_enc = JSON `{accessKey,secretKey}`) |
| `provider_id` | INTEGER FK → `providers(id)` | |
| `environment` | TEXT CHECK (`dev`/`qa`/`staging`/`prod`) | |
| `folder_id` | INTEGER FK → `folders(id)` ON DELETE SET NULL | Nullable |
| `description` | TEXT | Nullable freeform note (stored in clear) |
| `value_enc` | BLOB | `nonce \|\| ciphertext \|\| Poly1305 tag` |
| `value_hash` | BLOB | Keyed HMAC of the plaintext for duplicate detection (not reversible) |
| `custom_fields` | TEXT DEFAULT `'{}'` | JSON key-value metadata (not secret, stored in clear) |
| `is_favorite` | INTEGER DEFAULT `0` | 1 = pinned to top of list |
| `totp_enc` | BLOB | Nullable; encrypted TOTP seed. Same AEAD scheme as `value_enc` with domain tag `\|totp` |
| `created_at` | INTEGER | Unix timestamp |
| `updated_at` | INTEGER | Unix timestamp |
| `last_used_at` | INTEGER | Nullable; updated on reveal/copy |
| `expires_at` | INTEGER | Nullable; Unix timestamp |
| `rotation_days` | INTEGER | Nullable; days between recommended rotations |
| `is_archived` | INTEGER DEFAULT `0` | Soft-delete flag |

**Indexes:** `provider_id`, `environment`, `expires_at`, `value_hash`, `item_type`, `is_favorite`

---

### `tags` + `secret_tags`

Many-to-many tags.

| Column | Type | Description |
|--------|------|-------------|
| `tags.id` | INTEGER PK AUTOINCREMENT | |
| `tags.name` | TEXT UNIQUE | Tag label |
| `secret_tags.secret_id` | INTEGER FK → `secrets(id)` ON DELETE CASCADE | |
| `secret_tags.tag_id` | INTEGER FK → `tags(id)` ON DELETE CASCADE | |

---

### `secret_history` — removed (migration 0006)

Earlier versions retained previous encrypted values on every `UpdateValue`. The
value-history feature was removed by product decision; migration `0006` drops the
table and purges any retained previous values on upgrade. `UpdateValue` now
overwrites in place and keeps no superseded copies.

---

### `audit_log` — append-only, tamper-evident

Every sensitive operation is written here. The hash chain makes any after-the-fact deletion or editing detectable.

| Column | Type | Description |
|--------|------|-------------|
| `seq` | INTEGER PK AUTOINCREMENT | Monotonically increasing |
| `ts` | INTEGER | Unix timestamp |
| `actor` | TEXT | Session identifier, e.g. `"ui"` |
| `action` | TEXT | `create` / `reveal` / `update` / `delete` / `archive` / `unlock` / `lock` / `init` / `totp_set` / `set_custom_fields` / … |
| `target` | TEXT | Secret alias or empty string |
| `outcome` | TEXT | `allow` or `deny` |
| `detail` | TEXT | Freeform context (e.g. `"wrong password"`) |
| `prev_hash` | BLOB | SHA-256 of the previous row's `hash` field |
| `hash` | BLOB | `SHA-256(prev_hash ‖ canonical(record))` — the chain link |

---

### `settings`

Simple key-value config store. All values are strings.

| Key | Default | Description |
|-----|---------|-------------|
| `autolock_seconds` | `300` | Idle auto-lock timeout (0 = disabled) |
| `clipboard_clear_seconds` | `30` | How long before clipboard is wiped after a copy |
| `theme` | `dark` | `dark` or `light` |

---

### `schema_migrations`

Internal table used by the migration runner.

| Column | Type | Description |
|--------|------|-------------|
| `version` | INTEGER PK | Numeric prefix of the migration filename |
| `applied_at` | INTEGER | Unix timestamp when the migration was applied |

---

## Notes

- Foreign keys are enforced (`PRAGMA foreign_keys = ON`).
- WAL journal mode (`PRAGMA journal_mode = WAL`) for safe concurrent reads during a write.
- Single max-open-connection to simplify WAL serialization in a desktop app.
- File permissions are hardened to the current OS user on first open (Windows DACL / Unix `chmod 0600`).
- The database file itself is not encrypted at the OS level (app-layer encryption). `secrets.value_enc` and `totp_enc` are AEAD-encrypted; all other columns are stored in clear.
