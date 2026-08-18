import { BoolResult, IDResult, SecretSummary, HealthItem, AuditEntry, Provider, AddSecretInput, AddKeyPairInput, ImportPreviewResult, ImportCommitResult, AddProviderInput } from './types'

declare global {
  interface Window {
    go: {
      main: {
        App: {
          IsInitialized(): Promise<boolean>
          IsUnlocked(): Promise<boolean>
          InitVault(password: string): Promise<BoolResult>
          Unlock(password: string): Promise<BoolResult>
          Lock(): Promise<void>
          Touch(): Promise<void>
          HasRecoveryKey(): Promise<boolean>
          GenerateRecoveryKey(): Promise<string>
          RecoverWithKey(recoveryCode: string, newPassword: string): Promise<BoolResult>
          ListSecrets(search: string, provider: string, env: string, includeArchived: boolean): Promise<SecretSummary[]>
          RevealSecret(alias: string): Promise<string>
          AddSecret(input: AddSecretInput): Promise<IDResult>
          UpdateSecretValue(alias: string, newValue: string): Promise<BoolResult>
          DeleteSecret(alias: string): Promise<BoolResult>
          ArchiveSecret(alias: string, archived: boolean): Promise<BoolResult>
          TagSecret(alias: string, tag: string): Promise<BoolResult>
          GetCustomFields(alias: string): Promise<string>
          SetCustomFields(alias: string, jsonFields: string): Promise<BoolResult>
          GetHealth(): Promise<HealthItem[]>
          GetAuditLog(limit: number): Promise<AuditEntry[]>
          VerifyAuditChain(): Promise<number>
          ExportBackup(password: string): Promise<Uint8Array>
          ImportBackup(data: number[], password: string): Promise<BoolResult>
          ListProviders(): Promise<Provider[]>
          AddProvider(input: AddProviderInput): Promise<BoolResult>
          DeleteProvider(key: string): Promise<BoolResult>
          GetSetting(key: string): Promise<string>
          SetSetting(key: string, value: string): Promise<BoolResult>
          GetVaultPath(): Promise<string>
          GetVersion(): Promise<string>
          ResetVault(): Promise<BoolResult>
          AddKeyPair(input: AddKeyPairInput): Promise<{ accessKeyId: number; secretKeyId: number; err?: string }>
          ImportPreview(filePath: string, cm: import('./types').ColMapDTO): Promise<ImportPreviewResult>
          ImportCommit(filePath: string, cm: import('./types').ColMapDTO): Promise<ImportCommitResult>
        }
      }
    }
  }
}

const go = () => window.go.main.App

export const api = {
  isInitialized: ()                          => go().IsInitialized(),
  isUnlocked:    ()                          => go().IsUnlocked(),
  initVault:     (pw: string)                => go().InitVault(pw),
  unlock:        (pw: string)                => go().Unlock(pw),
  lock:          ()                          => go().Lock(),
  touch:         ()                          => go().Touch(),

  hasRecoveryKey:      ()                              => go().HasRecoveryKey(),
  generateRecoveryKey: ()                              => go().GenerateRecoveryKey(),
  recoverWithKey:      (code: string, newPw: string)   => go().RecoverWithKey(code, newPw),

  listSecrets:   (search='', provider='', env='', includeArchived=false) =>
                   go().ListSecrets(search, provider, env, includeArchived),
  revealSecret:  (alias: string)             => go().RevealSecret(alias),
  addSecret:     (input: AddSecretInput)     => go().AddSecret(input),
  updateValue:   (alias: string, val: string)=> go().UpdateSecretValue(alias, val),
  deleteSecret:  (alias: string)             => go().DeleteSecret(alias),
  archiveSecret: (alias: string, v: boolean) => go().ArchiveSecret(alias, v),
  tagSecret:     (alias: string, tag: string)=> go().TagSecret(alias, tag),

  getCustomFields: (alias: string)                     => go().GetCustomFields(alias),
  setCustomFields: (alias: string, json: string)       => go().SetCustomFields(alias, json),

  getHealth:     ()                          => go().GetHealth(),
  getAuditLog:   (n=200)                     => go().GetAuditLog(n),
  verifyChain:   ()                          => go().VerifyAuditChain(),

  exportBackup:  (pw: string)                => go().ExportBackup(pw),
  importBackup:  (data: number[], pw: string)=> go().ImportBackup(data, pw),

  listProviders: ()                          => go().ListProviders(),
  addProvider:   (input: AddProviderInput)   => go().AddProvider(input),
  deleteProvider:(key: string)               => go().DeleteProvider(key),
  getSetting:    (key: string)               => go().GetSetting(key),
  setSetting:    (key: string, val: string)  => go().SetSetting(key, val),
  getVaultPath:  ()                          => go().GetVaultPath(),
  getVersion:    ()                          => go().GetVersion(),
  resetVault:    ()                          => go().ResetVault(),

  addKeyPair:    (input: AddKeyPairInput)    => go().AddKeyPair(input),

  importPreview: (path: string, cm: import('./types').ColMapDTO) => go().ImportPreview(path, cm),
  importCommit:  (path: string, cm: import('./types').ColMapDTO) => go().ImportCommit(path, cm),
}
