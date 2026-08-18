export type SecretSummary = {
  id: number
  alias: string
  providerKey: string
  providerName: string
  environment: string
  tags: string[]
  folderName: string
  description: string
  expiresAt: number | null
  lastUsedAt: number | null
  isArchived: boolean
  customFields: string
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
  providerKey: string
  environment: string
  description: string
  value: string
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
