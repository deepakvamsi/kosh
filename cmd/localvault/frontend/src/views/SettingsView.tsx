import { useEffect, useState } from 'react'
import { api } from '../api'
import { applyTheme } from '../lib/theme'
import { Settings, FolderOpen, AlertTriangle, RotateCcw, KeyRound } from 'lucide-react'

const SETTINGS = [
  { key: 'autolock_seconds',        label: 'Auto-lock timeout',    unit: 'seconds', default: '300' },
  { key: 'clipboard_clear_seconds', label: 'Clipboard auto-clear', unit: 'seconds', default: '30'  },
  { key: 'theme',                   label: 'Theme',                unit: '',        default: 'dark' },
]

export default function SettingsView({ onResetDone }: { onResetDone?: () => void }) {
  const [values, setValues]     = useState<Record<string, string>>({})
  const [vaultPath, setVaultPath] = useState('')
  const [saved, setSaved]       = useState(false)
  const [resetting, setResetting] = useState(false)
  const [resetError, setResetError] = useState('')

  const [hasRecovery, setHasRecovery] = useState(false)
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null)
  const [genLoading, setGenLoading] = useState(false)
  const [genError, setGenError] = useState('')

  useEffect(() => {
    api.getVaultPath().then(setVaultPath)
    api.hasRecoveryKey().then(setHasRecovery)
    Promise.all(SETTINGS.map(s => api.getSetting(s.key).then(v => [s.key, v || s.default] as const)))
      .then(pairs => setValues(Object.fromEntries(pairs)))
  }, [])

  async function handleGenerateRecovery() {
    const warn = hasRecovery
      ? 'This replaces your existing recovery key — the old one will stop working. Continue?'
      : 'Generate a recovery key? Anyone who has it can reset your master password, so store it somewhere safe and offline.'
    if (!confirm(warn)) return
    setGenLoading(true); setGenError('')
    try {
      const code = await api.generateRecoveryKey()
      setRecoveryCode(code)
      setHasRecovery(true)
    } catch (e: any) { setGenError(String(e)) }
    finally { setGenLoading(false) }
  }

  function copyRecovery() {
    if (recoveryCode) navigator.clipboard?.writeText(recoveryCode)
  }

  async function handleSave() {
    await Promise.all(SETTINGS.map(s => api.setSetting(s.key, values[s.key] ?? s.default)))
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  async function handleReset() {
    const confirmed = confirm(
      'DANGER: This will permanently delete your vault database and all stored secrets.\n\n' +
      'The app will restart as if freshly installed.\n\n' +
      'Type "RESET" in the next prompt to confirm.'
    )
    if (!confirmed) return
    const typed = prompt('Type RESET to confirm vault deletion:')
    if (typed !== 'RESET') { alert('Cancelled — vault was not deleted.'); return }

    setResetting(true); setResetError('')
    try {
      const res = await api.resetVault()
      if (res.err) {
        setResetError(res.err)
      } else {
        onResetDone?.()
      }
    } catch (e: any) { setResetError(String(e)) }
    finally { setResetting(false) }
  }

  return (
    <div className="flex h-full flex-col gap-6 overflow-y-auto p-6 max-w-lg">
      <h2 className="flex items-center gap-2 text-sm font-semibold">
        <Settings className="h-4 w-4" /> Settings
      </h2>

      <div className="flex flex-col gap-4">
        {SETTINGS.map(s => (
          <label key={s.key} className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
            {s.label} {s.unit && <span className="text-[10px]">({s.unit})</span>}
            {s.key === 'theme' ? (
              <select
                value={values[s.key] ?? s.default}
                onChange={e => {
                  const val = e.target.value
                  setValues(v => ({ ...v, [s.key]: val }))
                  applyTheme(val)              // switch instantly
                  api.setSetting('theme', val) // and persist right away
                }}
                className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none"
              >
                <option value="dark">Dark</option>
                <option value="light">Light</option>
              </select>
            ) : (
              <input
                type="number"
                value={values[s.key] ?? s.default}
                onChange={e => setValues(v => ({ ...v, [s.key]: e.target.value }))}
                className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]"
              />
            )}
          </label>
        ))}
      </div>

      <button
        onClick={handleSave}
        className="w-fit rounded-lg bg-[rgb(var(--accent))] px-4 py-2.5 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] transition-colors"
      >
        {saved ? 'Saved ✓' : 'Save Settings'}
      </button>

      <div className="rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4">
        <p className="mb-1 flex items-center gap-2 text-xs font-medium text-[rgb(var(--text-muted))]">
          <FolderOpen className="h-3.5 w-3.5" /> Vault location
        </p>
        <code className="text-xs text-[rgb(var(--text))] select-text break-all">{vaultPath}</code>
      </div>

      <div className="rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4 text-xs space-y-1 text-[rgb(var(--text-muted))]">
        <p className="font-medium text-[rgb(var(--text))]">Security posture</p>
        <p>• No network connections — air-sealed by design</p>
        <p>• Screenshot-blocked on Windows (WDA_EXCLUDEFROMCAPTURE)</p>
        <p>• Argon2id key derivation, XChaCha20-Poly1305 AEAD</p>
        <p>• Tamper-evident hash-chained audit log</p>
        <p>• Clipboard auto-clears after reveal/copy</p>
      </div>

      <div className="rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4 flex flex-col gap-3">
        <p className="flex items-center gap-2 text-xs font-medium text-[rgb(var(--text))]">
          <KeyRound className="h-3.5 w-3.5" /> Recovery key
        </p>
        <p className="text-xs text-[rgb(var(--text-muted))]">
          A recovery key lets you reset a forgotten master password. Store it offline —
          anyone who has it can re-key your vault.
        </p>

        {recoveryCode ? (
          <div className="flex flex-col gap-2">
            <p className="text-xs font-medium text-[rgb(var(--danger))]">
              Save this now — it will not be shown again.
            </p>
            <code className="select-text break-all rounded-lg border border-[rgb(var(--accent))]/40 bg-[rgb(var(--bg))] p-3 font-mono text-xs text-[rgb(var(--text))]">
              {recoveryCode}
            </code>
            <div className="flex gap-2">
              <button
                onClick={copyRecovery}
                className="rounded-lg border border-[rgb(var(--border))] px-3 py-1.5 text-xs hover:bg-white/5"
              >
                Copy
              </button>
              <button
                onClick={() => setRecoveryCode(null)}
                className="rounded-lg bg-[rgb(var(--accent))] px-3 py-1.5 text-xs font-medium text-white hover:bg-[rgb(var(--accent-hover))]"
              >
                I've saved it
              </button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-1.5">
            <button
              onClick={handleGenerateRecovery}
              disabled={genLoading}
              className="flex w-fit items-center gap-2 rounded-lg border border-[rgb(var(--border))] px-4 py-2 text-sm hover:bg-white/5 disabled:opacity-50"
            >
              <KeyRound className="h-4 w-4" />
              {genLoading ? 'Generating…' : hasRecovery ? 'Regenerate recovery key' : 'Generate recovery key'}
            </button>
            {hasRecovery && <p className="text-xs text-[rgb(var(--success))]">A recovery key is configured.</p>}
            {genError && <p className="text-xs text-[rgb(var(--danger))]">{genError}</p>}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4 flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
          <p className="text-sm font-medium text-red-400">Danger Zone</p>
        </div>
        <p className="text-xs text-[rgb(var(--text-muted))]">
          <strong className="text-[rgb(var(--text))]">Reset Vault</strong> — permanently deletes the vault database
          and all stored secrets. The app will return to the first-run setup screen.
          This cannot be undone. Export a backup first if you need to keep your secrets.
        </p>
        {resetError && <p className="text-xs text-[rgb(var(--danger))]">{resetError}</p>}
        <button
          onClick={handleReset}
          disabled={resetting}
          className="flex w-fit items-center gap-2 rounded-lg border border-red-500/40 px-4 py-2 text-sm font-medium text-red-400 hover:bg-red-500/10 disabled:opacity-50 transition-colors"
        >
          <RotateCcw className="h-4 w-4" />
          {resetting ? 'Resetting…' : 'Reset Vault (delete all data)'}
        </button>
      </div>
    </div>
  )
}
