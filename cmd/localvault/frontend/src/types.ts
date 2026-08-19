export type ItemType = 'api_key' | 'login' | 'secure_note'

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
  value: string    // api_key
  username: string // login
  password: string // login
  note: string     // secure_note
  err?: string
}

export type BoolResult = { ok: boolean; err?: string }
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
  value: string     // api_key
  username?: string // login
  password?: string // login
  note?: string     // secure_note
  expiresAt?: number | null
  rotationDays?: number | null
}

export type AddKeyPairInput = {
  accessKeyAlias: string
  accessKeyValue: string
  secretKeyAlias: string
  secretKeyValue: string
  providerKey: string
  environment: string
  description: string
  expiresAt?: number | null
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
