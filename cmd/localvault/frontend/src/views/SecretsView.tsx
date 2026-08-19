import { useState, useEffect, useCallback, Fragment } from 'react'
import { api } from '../api'
import { SecretSummary, AddSecretInput, Provider, RevealedItem, ItemType } from '../types'
import { Plus, Search, Eye, EyeOff, Copy, Trash2, Archive, RotateCcw, KeyRound, Link2, User, FileText, Star } from 'lucide-react'
import CustomFieldsPanel from '../components/CustomFieldsPanel'
import StrengthBar from '../components/StrengthBar'
import TOTPPanel from '../components/TOTPPanel'

type RevealState = { alias: string; item: RevealedItem; timer: ReturnType<typeof setTimeout> | null }

const ITEM_META: Record<ItemType, { label: string; Icon: typeof KeyRound }> = {
  api_key:     { label: 'API key',  Icon: KeyRound },
  login:       { label: 'Login',    Icon: User },
  keypair:     { label: 'Key pair', Icon: Link2 },
  secure_note: { label: 'Note',     Icon: FileText },
}

// primarySecret is the single string the row-level Copy button yields for an item.
function primarySecret(r: RevealedItem): string {
  if (r.itemType === 'login') return r.password
  if (r.itemType === 'secure_note') return r.note
  if (r.itemType === 'keypair') return r.secretKey
  return r.value
}

export default function SecretsView() {
  const [secrets, setSecrets] = useState<SecretSummary[]>([])
  const [providers, setProviders] = useState<Provider[]>([])
  const [search, setSearch] = useState('')
  const [filterEnv, setFilterEnv] = useState('')
  const [filterProv, setFilterProv] = useState('')
  const [includeArchived, setIncludeArchived] = useState(false)
  const [revealed, setRevealed] = useState<RevealState | null>(null)
  const [addOpen, setAddOpen] = useState(false)
  const [copied, setCopied] = useState('')
  const [loadErr, setLoadErr] = useState('')

  const load = useCallback(async () => {
    setLoadErr('')
    try {
      const [s, p] = await Promise.all([
        api.listSecrets(search, filterProv, filterEnv, includeArchived),
        api.listProviders(),
      ])
      setSecrets(s ?? [])
      setProviders(p ?? [])
    } catch (e: any) {
      setLoadErr(String(e?.message ?? e))
    }
  }, [search, filterProv, filterEnv, includeArchived])

  useEffect(() => { load() }, [load])

  function clearRevealed() {
    if (revealed?.timer) clearTimeout(revealed.timer)
    setRevealed(null)
  }

  async function handleReveal(alias: string) {
    if (revealed?.alias === alias) { clearRevealed(); return }
    clearRevealed()
    try {
      const item = await api.revealItem(alias)
      if (item.err) { alert('Reveal failed: ' + item.err); return }
      const timer = setTimeout(() => setRevealed(null), 30_000)
      setRevealed({ alias, item, timer })
    } catch (e: any) { alert('Reveal failed: ' + e) }
  }

  // copyValue writes an already-revealed string to the clipboard and auto-clears it after
  // 30s (only if it hasn't since changed), matching the reveal auto-hide window.
  async function copyValue(marker: string, value: string) {
    await navigator.clipboard.writeText(value)
    setCopied(marker)
    setTimeout(() => setCopied(''), 2000)
    setTimeout(async () => {
      try { const cur = await navigator.clipboard.readText(); if (cur === value) await navigator.clipboard.writeText('') } catch {}
    }, 30_000)
  }

  // handleCopy copies an item's primary secret (password for a login, note body for a
  // secure note, value for an API key) from the row action button.
  async function handleCopy(alias: string) {
    const item = revealed?.alias === alias ? revealed.item : await api.revealItem(alias)
    if (item.err) { alert('Copy failed: ' + item.err); return }
    await copyValue(alias, primarySecret(item))
  }

  async function handleDelete(alias: string) {
    if (!confirm(`Delete secret "${alias}"? This cannot be undone.`)) return
    await api.deleteSecret(alias)
    load()
  }

  async function handleArchive(alias: string, archived: boolean) {
    await api.archiveSecret(alias, archived)
    load()
  }

  const envBadge = (e: string) => {
    const m: Record<string, string> = {
      prod: 'bg-red-500/15 text-red-400',
      staging: 'bg-orange-500/15 text-orange-400',
      qa: 'bg-yellow-500/15 text-yellow-400',
      dev: 'bg-green-500/15 text-green-400',
    }
    return m[e] ?? 'bg-[rgb(var(--border)/0.5)] text-[rgb(var(--text-muted))]'
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-[rgb(var(--border))] px-6 py-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[rgb(var(--text-muted))]" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by name or description…"
            className="w-full rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] py-2 pl-9 pr-3 text-sm outline-none focus:border-[rgb(var(--accent))]"
          />
        </div>
        <select value={filterEnv} onChange={e => setFilterEnv(e.target.value)}
          className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-3 py-2 text-sm outline-none">
          <option value="">All envs</option>
          {['dev','qa','staging','prod'].map(e => <option key={e} value={e}>{e}</option>)}
        </select>
        <select value={filterProv} onChange={e => setFilterProv(e.target.value)}
          className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-3 py-2 text-sm outline-none">
          <option value="">All providers</option>
          {providers.map(p => <option key={p.key} value={p.key}>{p.name}</option>)}
        </select>
        <label className="flex items-center gap-1.5 text-xs text-[rgb(var(--text-muted))] cursor-pointer">
          <input type="checkbox" checked={includeArchived} onChange={e => setIncludeArchived(e.target.checked)} className="accent-[rgb(var(--accent))]" />
          Archived
        </label>

        <button onClick={() => setAddOpen(true)}
          className="flex items-center gap-2 rounded-lg bg-[rgb(var(--accent))] px-4 py-2 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] transition-colors">
          <Plus className="h-4 w-4" /> Add
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {loadErr && (
          <div className="m-4 flex items-center gap-3 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            <span className="font-medium">Failed to load secrets:</span>
            <span className="font-mono text-xs">{loadErr}</span>
            <button onClick={load} className="ml-auto rounded border border-red-500/30 px-2 py-1 text-xs hover:bg-red-500/20">
              Retry
            </button>
          </div>
        )}
        {!loadErr && secrets.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-4 text-sm text-[rgb(var(--text-muted))]">
            <KeyRound className="h-10 w-10 opacity-20" />
            <p className="font-medium text-[rgb(var(--text))]">Your vault is empty</p>
            <button onClick={() => setAddOpen(true)}
              className="flex items-center gap-2 rounded-lg bg-[rgb(var(--accent))] px-4 py-2 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))]">
              <Plus className="h-4 w-4" /> Add your first secret
            </button>
          </div>
        ) : (
          !loadErr && (
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-[rgb(var(--surface))] text-xs text-[rgb(var(--text-muted))] uppercase tracking-wider">
              <tr>
                {['Name','Provider','Env','Tags','Expires',''].map(h => (
                  <th key={h} className="px-4 py-3 text-left font-medium border-b border-[rgb(var(--border))]">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {secrets.map(s => {
                const meta = ITEM_META[s.itemType] ?? ITEM_META.api_key
                const TypeIcon = meta.Icon
                return (
                <Fragment key={s.id}>
                  <tr
                    className={`border-b border-[rgb(var(--border)/0.5)] hover:bg-white/3 transition-colors ${s.isArchived ? 'opacity-50' : ''}`}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <span title={meta.label}>
                          <TypeIcon className="h-3.5 w-3.5 text-[rgb(var(--text-muted))] shrink-0" />
                        </span>
                        {s.isFavorite && (
                          <Star className="h-3 w-3 fill-yellow-400 text-yellow-400 shrink-0" />
                        )}
                        <span className="font-mono font-medium">{s.alias}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-[rgb(var(--text-muted))]">{s.providerName}</td>
                    <td className="px-4 py-3">
                      <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${envBadge(s.environment)}`}>{s.environment}</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(s.tags ?? []).map(t => (
                          <span key={t} className="rounded bg-[rgb(var(--border)/0.6)] px-1.5 py-0.5 text-xs text-[rgb(var(--text-muted))]">{t}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-[rgb(var(--text-muted))]">
                      {s.expiresAt ? new Date(s.expiresAt * 1000).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5 justify-end">
                        <button onClick={async () => { await api.setFavorite(s.alias, !s.isFavorite); load() }}
                          title={s.isFavorite ? 'Unpin from favorites' : 'Pin to favorites'}
                          className={`rounded p-1.5 hover:bg-white/10 transition-colors ${s.isFavorite ? 'text-yellow-400' : 'text-[rgb(var(--text-muted))] hover:text-yellow-400'}`}>
                          <Star className={`h-3.5 w-3.5 ${s.isFavorite ? 'fill-yellow-400' : ''}`} />
                        </button>
                        <button onClick={() => handleReveal(s.alias)} title={revealed?.alias === s.alias ? 'Hide' : 'Reveal'}
                          className="rounded p-1.5 text-[rgb(var(--text-muted))] hover:bg-white/10 hover:text-[rgb(var(--text))]">
                          {revealed?.alias === s.alias ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                        </button>
                        <button onClick={() => handleCopy(s.alias)} title="Copy"
                          className={`rounded p-1.5 hover:bg-white/10 transition-colors ${copied === s.alias ? 'text-[rgb(var(--success))]' : 'text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))]'}`}>
                          <Copy className="h-3.5 w-3.5" />
                        </button>
                        <button onClick={() => handleArchive(s.alias, !s.isArchived)} title={s.isArchived ? 'Unarchive' : 'Archive'}
                          className="rounded p-1.5 text-[rgb(var(--text-muted))] hover:bg-white/10 hover:text-[rgb(var(--text))]">
                          {s.isArchived ? <RotateCcw className="h-3.5 w-3.5" /> : <Archive className="h-3.5 w-3.5" />}
                        </button>
                        <button onClick={() => handleDelete(s.alias)} title="Delete"
                          className="rounded p-1.5 text-[rgb(var(--text-muted))] hover:bg-red-500/10 hover:text-[rgb(var(--danger))]">
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                  {revealed?.alias === s.alias && (
                    <tr className="bg-[rgb(var(--accent)/0.05)]">
                      <td colSpan={6} className="px-4 py-2">
                        <RevealedFields item={revealed.item} onCopy={copyValue} copied={copied} />
                        <TOTPPanel alias={s.alias} hasTOTP={s.hasTOTP} onChanged={load} />
                        <CustomFieldsPanel
                          alias={s.alias}
                          initialJson={s.customFields}
                          onSaved={load}
                        />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )})}
            </tbody>
          </table>
          )
        )}
      </div>

      {addOpen && (
        <AddModal providers={providers} onClose={() => setAddOpen(false)} onSaved={load} />
      )}
    </div>
  )
}

// RevealedFields renders a revealed item's payload according to its type: a login shows
// separately-copyable username and (masked) password; a secure note shows its body; an
// API key shows its value. Every field has its own copy button.
function RevealedFields({ item, onCopy, copied }: {
  item: RevealedItem
  onCopy: (marker: string, value: string) => void
  copied: string
}) {
  const [showPw, setShowPw] = useState(false)

  const copyBtn = (marker: string, value: string) => (
    <button type="button" onClick={() => onCopy(marker, value)} title="Copy"
      className={`rounded p-1.5 hover:bg-white/10 ${copied === marker ? 'text-[rgb(var(--success))]' : 'text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))]'}`}>
      <Copy className="h-3.5 w-3.5" />
    </button>
  )

  const fieldRow = (label: string, value: string, marker: string, opts?: { mono?: boolean; masked?: boolean }) => (
    <div className="flex items-center gap-2">
      <span className="w-20 shrink-0 text-xs text-[rgb(var(--text-muted))]">{label}</span>
      <code className={`flex-1 truncate rounded border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-3 py-1.5 text-xs text-[rgb(var(--text))] select-text ${opts?.mono === false ? '' : 'font-mono'}`}>
        {opts?.masked && !showPw ? '••••••••••••' : value}
      </code>
      {opts?.masked && (
        <button type="button" onClick={() => setShowPw(v => !v)} title={showPw ? 'Hide' : 'Show'}
          className="rounded p-1.5 text-[rgb(var(--text-muted))] hover:bg-white/10 hover:text-[rgb(var(--text))]">
          {showPw ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
        </button>
      )}
      {copyBtn(marker, value)}
    </div>
  )

  return (
    <div className="flex flex-col gap-2">
      {item.itemType === 'login' && (
        <>
          {fieldRow('Username', item.username, 'reveal-user', { mono: false })}
          {fieldRow('Password', item.password, 'reveal-pass', { masked: true })}
        </>
      )}
      {item.itemType === 'secure_note' && (
        <div className="flex items-start gap-2">
          <span className="w-20 shrink-0 pt-1.5 text-xs text-[rgb(var(--text-muted))]">Note</span>
          <pre className="flex-1 whitespace-pre-wrap break-words rounded border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-3 py-1.5 font-sans text-xs text-[rgb(var(--text))] select-text">{item.note}</pre>
          {copyBtn('reveal-note', item.note)}
        </div>
      )}
      {item.itemType === 'keypair' && (
        <>
          {fieldRow('Access key', item.accessKey, 'reveal-ak')}
          {fieldRow('Secret key', item.secretKey, 'reveal-sk', { masked: true })}
        </>
      )}
      {item.itemType === 'api_key' && fieldRow('Value', item.value, 'reveal-val')}
      <span className="text-[11px] text-[rgb(var(--text-muted))]">Auto-hides in 30s · clipboard clears in 30s</span>
    </div>
  )
}

// AddModal is the single entry point for creating any vault item: API key, login, key
// pair, or secure note. One button, four tabs. Name, provider/environment and Description
// are shared across every type (Description always last); only the value fields in the
// middle switch. A key pair is ONE entry — access key + secret key encrypted together
// (itemType 'keypair') — not two linked secrets.
function AddModal({ providers, onClose, onSaved }: { providers: Provider[]; onClose: () => void; onSaved: () => void }) {
  const [mode, setMode] = useState<ItemType>('api_key')
  const [form, setForm] = useState<AddSecretInput>({ alias: '', providerKey: providers[0]?.key ?? 'openai', environment: 'dev', description: '', value: '', username: '', password: '', note: '', accessKey: '', secretKey: '' })
  const [showVal, setShowVal] = useState(false)
  const [showPw, setShowPw] = useState(false)
  const [showAK, setShowAK] = useState(false)
  const [showSK, setShowSK] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const inputCls = 'rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]'
  const labelCls = 'flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]'
  const eyeBtn = 'absolute right-2 top-1/2 -translate-y-1/2 text-[rgb(var(--text-muted))]'
  const set = (k: keyof AddSecretInput) => (e: { target: { value: string } }) => setForm(f => ({ ...f, [k]: e.target.value }))

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    if (!form.alias) { setError('Name is required'); return }
    if (mode === 'api_key' && !form.value) { setError('A secret value is required'); return }
    if (mode === 'login' && (!form.username || !form.password)) { setError('Username and password are required'); return }
    if (mode === 'keypair' && (!form.accessKey || !form.secretKey)) { setError('Access key and secret key are required'); return }
    if (mode === 'secure_note' && !form.note) { setError('Note body is required'); return }
    setLoading(true)
    try {
      const res = await api.addSecret({ ...form, itemType: mode })
      if (res.err) setError(res.err)
      else { onSaved(); onClose() }
    } catch (e: any) { setError(String(e)) }
    finally { setLoading(false) }
  }

  const TABS: { type: ItemType; label: string; Icon: typeof KeyRound }[] = [
    { type: 'api_key',     label: 'API key',  Icon: KeyRound },
    { type: 'login',       label: 'Login',    Icon: User },
    { type: 'keypair',     label: 'Key pair', Icon: Link2 },
    { type: 'secure_note', label: 'Note',     Icon: FileText },
  ]

  const namePlaceholder =
    mode === 'login'       ? 'GITHUB_ACCOUNT' :
    mode === 'secure_note' ? 'RECOVERY_CODES' :
    mode === 'keypair'     ? 'AWS_BEDROCK_PROD' :
                             'MY_API_KEY'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-6 shadow-2xl">
        <h2 className="mb-4 text-base font-semibold">Add</h2>

        <div className="mb-4 grid grid-cols-4 gap-2">
          {TABS.map(({ type, label, Icon }) => (
            <button key={type} type="button" onClick={() => { setMode(type); setError('') }}
              className={`flex flex-col items-center gap-1 rounded-lg border px-2 py-2.5 text-xs font-medium transition-colors ${mode === type ? 'border-[rgb(var(--accent))] bg-[rgb(var(--accent)/0.1)] text-[rgb(var(--accent))]' : 'border-[rgb(var(--border))] text-[rgb(var(--text-muted))] hover:bg-white/5'}`}>
              <Icon className="h-4 w-4" /> {label}
            </button>
          ))}
        </div>

        <form onSubmit={submit} className="flex flex-col gap-3">
          {/* Name — shared, always first */}
          <label className={labelCls}>
            Name
            <input value={form.alias} onChange={set('alias')} placeholder={namePlaceholder} autoFocus className={inputCls} />
          </label>

          {/* Provider/Service + Environment — shared */}
          <div className="grid grid-cols-2 gap-3">
            <label className={labelCls}>
              {mode === 'login' ? 'Service' : 'Provider'}
              <select value={form.providerKey} onChange={set('providerKey')} className={inputCls}>
                {providers.map(p => <option key={p.key} value={p.key}>{p.name}</option>)}
              </select>
            </label>
            <label className={labelCls}>
              Environment
              <select value={form.environment} onChange={set('environment')} className={inputCls}>
                {['dev','qa','staging','prod'].map(v => <option key={v} value={v}>{v}</option>)}
              </select>
            </label>
          </div>

          {/* Type-specific value fields */}
          {mode === 'api_key' && (
            <label className={labelCls}>
              Secret value
              <div className="relative">
                <input type={showVal ? 'text' : 'password'} value={form.value} onChange={set('value')} placeholder="sk-…" className={`w-full pr-10 ${inputCls}`} />
                <button type="button" onClick={() => setShowVal(v => !v)} className={eyeBtn}>{showVal ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
              </div>
            </label>
          )}

          {mode === 'login' && (
            <>
              <label className={labelCls}>
                Username
                <input value={form.username} onChange={set('username')} placeholder="you@example.com" autoComplete="off" className={inputCls} />
              </label>
              <label className={labelCls}>
                Password
                <div className="relative">
                  <input type={showPw ? 'text' : 'password'} value={form.password} onChange={set('password')} placeholder="••••••••" autoComplete="new-password" className={`w-full pr-10 ${inputCls}`} />
                  <button type="button" onClick={() => setShowPw(v => !v)} className={eyeBtn}>{showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
                </div>
              </label>
              <StrengthBar value={form.password ?? ''} />
            </>
          )}

          {mode === 'keypair' && (
            <>
              <label className={labelCls}>
                Access key
                <div className="relative">
                  <input type={showAK ? 'text' : 'password'} value={form.accessKey} onChange={set('accessKey')} placeholder="AKIA…" className={`w-full pr-10 font-mono ${inputCls}`} />
                  <button type="button" onClick={() => setShowAK(v => !v)} className={eyeBtn}>{showAK ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
                </div>
              </label>
              <label className={labelCls}>
                Secret key
                <div className="relative">
                  <input type={showSK ? 'text' : 'password'} value={form.secretKey} onChange={set('secretKey')} placeholder="wJalrXUtn…" className={`w-full pr-10 font-mono ${inputCls}`} />
                  <button type="button" onClick={() => setShowSK(v => !v)} className={eyeBtn}>{showSK ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
                </div>
              </label>
            </>
          )}

          {mode === 'secure_note' && (
            <label className={labelCls}>
              Note
              <textarea value={form.note} onChange={set('note')} rows={5} placeholder="Recovery codes, connection strings, private notes…" className={`resize-y ${inputCls}`} />
            </label>
          )}

          {/* Description — shared, always last */}
          <label className={labelCls}>
            Description
            <input value={form.description} onChange={set('description')} placeholder="Optional" className={inputCls} />
          </label>

          {error && <p className="text-xs text-[rgb(var(--danger))]">{error}</p>}
          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose} className="flex-1 rounded-lg border border-[rgb(var(--border))] py-2.5 text-sm hover:bg-white/5">Cancel</button>
            <button type="submit" disabled={loading} className="flex-1 rounded-lg bg-[rgb(var(--accent))] py-2.5 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] disabled:opacity-50">
              {loading ? 'Saving…' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

