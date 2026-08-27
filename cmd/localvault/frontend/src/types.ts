export type ItemType = 'api_key' | 'login' | 'secure_note' | 'keypair'

export type SecretSummary = {
  id: number
  alias: string
  itemType: ItemType
  providerKey: string
  providerName: string
  environment: string
  tags: string[]
  folderName: string
  description: string
  expiresAt: number | null
  lastUsedAt: number | null
  isArchived: boolean
  isFavorite: boolean
  hasTOTP: boolean
  customFields: string
}

// RevealedItem is the decoded result of RevealItem — only the fields relevant to
// itemType are populated.
export type RevealedItem = {
  itemType: ItemType
  value: string     // api_key
  username: string  // login
  password: string  // login
  note: string      // secure_note
  accessKey: string // keypair
  secretKey: string // keypair
  err?: string
}

export type BoolResult = { ok: boolean; err?: string }

// BoolQuery is a boolean the backend had to read from the database, so the read can
// fail. Check `err` before trusting `value` — for "is there a vault?" and "is there a
// recovery key?" a wrong `false` is worse than showing an error.
export type BoolQuery = { value: boolean; err?: string }

// KdfParams describes the Argon2id cost protecting the vault, plus what this machine
// could sustain. `canStrengthen` is the backend's own comparison — trust it rather than
// re-deriving the comparison in the UI.
export type KdfParams = {
  time: number
  memoryKiB: number
  threads: number
  suggestedTime: number
  suggestedMemoryKiB: number
  canStrengthen: boolean
  err?: string
}

// SecretList separates "no secrets" from "could not read the secrets". `items` is always
// an array, never null.
export type SecretList = { items: SecretSummary[]; err?: string }
export type IDResult   = { id: number; err?: string }

export type HealthItem = {
  secretId: number
  alias: string
  status: 'healthy' | 'warning' | 'critical'
  flags: string[]
  score: number
  dupAliases: string[]
}

export type AuditEntry = {
  seq: number
  ts: number
  actor: string
  action: string
  target: string
  outcome: 'allow' | 'deny'
  detail: string
}

export type Provider = {
  key: string
  name: string
  category: string
  builtin: boolean
}

export type AddProviderInput = {
  key: string
  name: string
  category: string
}

export type AddSecretInput = {
  alias: string
  itemType?: ItemType // defaults to 'api_key' on the backend
  providerKey: string
  environment: string
  description: string
  value: string      // api_key
  username?: string  // login
  password?: string  // login
  note?: string      // secure_note
  accessKey?: string // keypair
  secretKey?: string // keypair
  expiresAt?: number | null
  rotationDays?: number | null
}

// UpdateSecretInput edits an existing secret. Description is always applied. The
// type-specific value fields are optional — leave them empty to keep the current value,
// or supply the full set for the item's type to rotate it.
export type UpdateSecretInput = {
  alias: string
  description: string
  value?: string     // api_key
  username?: string  // login
  password?: string  // login
  note?: string      // secure_note
  accessKey?: string // keypair
  secretKey?: string // keypair
}

export type ColMapDTO = {
  alias: number
  value: number
  providerKey: number
  environment: number
  description: number
  expiresAt: number
}

export type ImportRowDTO = {
  sourceRow: number
  alias: string
  value: string
  providerKey: string
  environment: string
  description: string
  expiresAt: number | null
  status: 'pending' | 'duplicate' | 'invalid' | 'imported' | 'skipped'
  statusNote: string
}

export type ImportPreviewResult = {
  headers: string[]
  rows: ImportRowDTO[]
  colMap: ColMapDTO
  errors: string[]
}

export type ImportCommitResult = {
  imported: number
  skipped: number
  duplicate: number
  invalid: number
  errors: string[]
}
