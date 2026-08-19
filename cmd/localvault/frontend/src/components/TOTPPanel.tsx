import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import { Shield, Clock, Plus, Trash2, History, Eye } from 'lucide-react'

type TOTPPanelProps = { alias: string; hasTOTP: boolean; onChanged: () => void }

export default function TOTPPanel({ alias, hasTOTP, onChanged }: TOTPPanelProps) {
  const [open, setOpen]     = useState(false)
  const [seed, setSeed]     = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState('')
  const [code, setCode]     = useState('')
  const [remaining, setRemaining] = useState(30)
  const [polling, setPolling]     = useState(false)

  const fetchCode = useCallback(async () => {
    if (!hasTOTP) return
    const res = await api.getTOTPCode(alias)
    if (!res.err) {
      setCode(res.code)
      setRemaining(res.remaining)
    }
  }, [alias, hasTOTP])

  useEffect(() => {
    if (!open || !hasTOTP) return
    setPolling(true)
    fetchCode()
    const id = setInterval(fetchCode, 1000)
    return () => { clearInterval(id); setPolling(false) }
  }, [open, hasTOTP, fetchCode])

  async function saveSeed(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true); setError('')
    try {
      const res = await api.setTOTP(alias, seed)
      if (res.err) setError(res.err)
      else { setSeed(''); onChanged() }
    } catch (e: any) { setError(String(e)) }
    finally { setSaving(false) }
  }

  async function removeSeed() {
    if (!confirm('Remove the TOTP seed for this secret?')) return
    setSaving(true)
    try {
      await api.setTOTP(alias, '')
      onChanged()
    } finally { setSaving(false) }
  }

  const pct = Math.round((remaining / 30) * 100)
  const danger = remaining <= 5

  return (
    <div className="border-t border-[rgb(var(--border)/0.4)]">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex w-full items-center gap-2 px-4 py-2 text-xs text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))] transition-colors"
      >
        <Shield className="h-3 w-3" />
        2FA / TOTP
        {hasTOTP && (
          <span className="rounded bg-green-500/15 px-1.5 py-0.5 text-[10px] text-green-400">active</span>
        )}
        <span className="ml-auto text-[rgb(var(--text-muted))]">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="px-4 pb-3 flex flex-col gap-3">
          {hasTOTP ? (
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-3">
                <code className={`text-2xl font-mono font-bold tracking-widest ${danger ? 'text-[rgb(var(--danger))]' : 'text-[rgb(var(--text))]'}`}>
                  {code || '------'}
                </code>
                <div className="flex flex-col gap-1 flex-1">
                  <div className="h-1.5 w-full rounded-full bg-[rgb(var(--border))]">
                    <div
                      className={`h-1.5 rounded-full transition-all ${danger ? 'bg-[rgb(var(--danger))]' : 'bg-[rgb(var(--success))]'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-[10px] text-[rgb(var(--text-muted))]">{remaining}s remaining</span>
                </div>
                <button onClick={removeSeed} title="Remove TOTP seed"
                  className="text-[rgb(var(--text-muted))] hover:text-[rgb(var(--danger))]">
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={saveSeed} className="flex flex-col gap-2">
              <p className="text-xs text-[rgb(var(--text-muted))]">
                Paste the base32 TOTP seed from the service's 2FA setup page.
              </p>
              <div className="flex gap-2">
                <input
                  value={seed}
                  onChange={e => setSeed(e.target.value)}
                  placeholder="JBSWY3DPEHPK3PXP…"
                  className="flex-1 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-2 py-1.5 font-mono text-xs text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]"
                />
                <button type="submit" disabled={saving || !seed.trim()}
                  className="flex items-center gap-1 rounded bg-[rgb(var(--accent)/0.15)] px-3 py-1.5 text-xs font-medium text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent)/0.25)] disabled:opacity-50">
                  <Plus className="h-3 w-3" /> Save
                </button>
              </div>
              {error && <p className="text-xs text-[rgb(var(--danger))]">{error}</p>}
            </form>
          )}
        </div>
      )}
    </div>
  )
}
