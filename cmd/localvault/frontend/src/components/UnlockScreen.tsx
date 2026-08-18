import React, { useState } from 'react'
import { api } from '../api'
import { Eye, EyeOff } from 'lucide-react'
import Brandmark from './Brandmark'

type Props = {
  onUnlocked: () => void
}

export default function UnlockScreen({ onUnlocked }: Props) {
  const [password, setPassword] = useState('')
  const [show, setShow] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [isNew, setIsNew] = useState<boolean | null>(null)
  const [confirm, setConfirm] = useState('')
  const [lockSeconds, setLockSeconds] = useState(0)

  const fmtWait = (s: number) => (s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`)

  // Recovery flow
  const [recoverMode, setRecoverMode] = useState(false)
  const [hasRecovery, setHasRecovery] = useState(false)
  const [recCode, setRecCode] = useState('')
  const [recNewPw, setRecNewPw] = useState('')
  const [recConfirm, setRecConfirm] = useState('')

  React.useEffect(() => {
    api.isInitialized().then(v => setIsNew(!v))
    api.hasRecoveryKey().then(setHasRecovery)
    api.unlockStatus().then(setLockSeconds).catch(() => {})
  }, [])

  // Count the lockout down once per second; it resumes correctly after a restart because
  // the backend persists the remaining time.
  const locked = lockSeconds > 0
  React.useEffect(() => {
    if (!locked) return
    const id = setInterval(() => setLockSeconds(s => (s <= 1 ? 0 : s - 1)), 1000)
    return () => clearInterval(id)
  }, [locked])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!password) return

    if (isNew && password !== confirm) {
      setError('Passwords do not match')
      return
    }
    if (isNew && password.length < 12) {
      setError('Master password must be at least 12 characters')
      return
    }

    setLoading(true)
    try {
      const res = isNew ? await api.initVault(password) : await api.unlock(password)
      if (res.err) {
        const tooMany = res.err.includes('too many failed')
        setError(tooMany ? 'Too many failed attempts — temporarily locked' : res.err === 'vault: wrong password' ? 'Wrong password' : res.err)
        // Refresh the lockout countdown (a failed attempt may have just tripped it).
        if (!isNew) api.unlockStatus().then(setLockSeconds).catch(() => {})
      } else {
        onUnlocked()
      }
    } catch (e: any) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  async function handleRecover(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!recCode.trim()) { setError('Enter your recovery key'); return }
    if (recNewPw.length < 12) { setError('New master password must be at least 12 characters'); return }
    if (recNewPw !== recConfirm) { setError('Passwords do not match'); return }

    setLoading(true)
    try {
      const res = await api.recoverWithKey(recCode, recNewPw)
      if (res.err) {
        setError(res.err === 'vault: invalid recovery key' ? 'Invalid recovery key' : res.err)
      } else {
        onUnlocked()
      }
    } catch (e: any) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  if (isNew === null) {
    return <div className="flex h-screen items-center justify-center text-[rgb(var(--text-muted))]">Loading…</div>
  }

  const subtitle = recoverMode
    ? 'Reset your master password with your recovery key'
    : isNew
      ? 'Create your vault — choose a strong master password'
      : 'Enter master password to unlock'

  return (
    <div className="flex h-screen flex-col items-center justify-center gap-8 bg-[rgb(var(--bg))] px-6">
      <div className="flex flex-col items-center gap-3">
        <Brandmark className="h-12 w-12 text-[rgb(var(--accent))]" />
        <span className="text-xl font-semibold tracking-tight">Kosh</span>
        <p className="text-sm text-[rgb(var(--text-muted))]">{subtitle}</p>
      </div>

      {recoverMode ? (
        <form onSubmit={handleRecover} className="flex w-full max-w-sm flex-col gap-3">
          <textarea
            value={recCode}
            onChange={e => setRecCode(e.target.value)}
            placeholder="Recovery key (XXXX-XXXX-…)"
            rows={2}
            autoFocus
            className="w-full resize-none rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-4 py-3 font-mono text-sm outline-none focus:border-[rgb(var(--accent))]"
          />
          <input
            type={show ? 'text' : 'password'}
            value={recNewPw}
            onChange={e => setRecNewPw(e.target.value)}
            placeholder="New master password"
            className="w-full rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-4 py-3 text-sm outline-none focus:border-[rgb(var(--accent))]"
          />
          <input
            type={show ? 'text' : 'password'}
            value={recConfirm}
            onChange={e => setRecConfirm(e.target.value)}
            placeholder="Confirm new password"
            className="w-full rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-4 py-3 text-sm outline-none focus:border-[rgb(var(--accent))]"
          />

          {error && <p className="text-xs text-[rgb(var(--danger))]">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="rounded-lg bg-[rgb(var(--accent))] px-4 py-3 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] disabled:opacity-50 transition-colors"
          >
            {loading ? '…' : 'Recover & set new password'}
          </button>
          <button
            type="button"
            onClick={() => { setRecoverMode(false); setError('') }}
            className="text-xs text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))]"
          >
            ← Back to unlock
          </button>
        </form>
      ) : (
        <form onSubmit={handleSubmit} className="flex w-full max-w-sm flex-col gap-3">
          <div className="relative">
            <input
              type={show ? 'text' : 'password'}
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Master password"
              autoFocus
              className="w-full rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-4 py-3 pr-10 text-sm outline-none focus:border-[rgb(var(--accent))] focus:ring-1 focus:ring-[rgb(var(--accent))]"
            />
            <button
              type="button"
              onClick={() => setShow(s => !s)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))]"
            >
              {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>

          {isNew && (
            <input
              type={show ? 'text' : 'password'}
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              placeholder="Confirm password"
              className="w-full rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-4 py-3 text-sm outline-none focus:border-[rgb(var(--accent))] focus:ring-1 focus:ring-[rgb(var(--accent))]"
            />
          )}

          {error && <p className="text-xs text-[rgb(var(--danger))]">{error}</p>}

          {!isNew && locked && (
            <p className="text-xs text-[rgb(var(--danger))]">
              Too many failed attempts. Try again in {fmtWait(lockSeconds)}.
            </p>
          )}

          <button
            type="submit"
            disabled={loading || (!isNew && locked)}
            className="rounded-lg bg-[rgb(var(--accent))] px-4 py-3 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] disabled:opacity-50 transition-colors"
          >
            {loading ? '…' : isNew ? 'Create Vault' : locked ? `Locked — ${fmtWait(lockSeconds)}` : 'Unlock'}
          </button>

          {!isNew && hasRecovery && (
            <button
              type="button"
              onClick={() => { setRecoverMode(true); setError('') }}
              className="text-xs text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))]"
            >
              Forgot password? Use recovery key
            </button>
          )}
        </form>
      )}

      <p className="text-xs text-[rgb(var(--text-muted))]">
        Local-only · No network · Air-sealed
      </p>
    </div>
  )
}
