import { useEffect, useState, useCallback } from 'react'
import { api } from '../api'
import { Provider, AddProviderInput } from '../types'
import { Cloud, Bot, GitBranch, Database, Layers, Box, Plus, Trash2, X } from 'lucide-react'

const catIcon: Record<string, React.ReactNode> = {
  cloud:    <Cloud     className="h-4 w-4" />,
  ai:       <Bot       className="h-4 w-4" />,
  vcs:      <GitBranch className="h-4 w-4" />,
  db:       <Database  className="h-4 w-4" />,
  platform: <Layers    className="h-4 w-4" />,
  custom:   <Box       className="h-4 w-4" />,
}

const CATEGORIES = [
  { key: 'cloud',    label: 'Cloud' },
  { key: 'ai',       label: 'AI / LLM' },
  { key: 'vcs',      label: 'Version Control' },
  { key: 'db',       label: 'Database' },
  { key: 'platform', label: 'Platform / DevOps' },
  { key: 'custom',   label: 'Custom' },
]

export default function ProvidersView() {
  const [providers, setProviders] = useState<Provider[]>([])
  const [showAdd, setShowAdd] = useState(false)

  const load = useCallback(() => {
    api.listProviders().then(p => setProviders(p ?? []))
  }, [])

  useEffect(() => { load() }, [load])

  const groups = providers.reduce<Record<string, Provider[]>>((acc, p) => {
    ;(acc[p.category] = acc[p.category] || []).push(p)
    return acc
  }, {})

  async function handleDelete(key: string) {
    if (!confirm(`Remove provider "${key}"? Secrets using it will keep their existing association.`)) return
    const res = await api.deleteProvider(key)
    if (res.err) alert(res.err)
    else load()
  }

  return (
    <div className="overflow-y-auto p-6">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-sm font-semibold">Providers / Vendors</h2>
        <button
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-2 rounded-lg bg-[rgb(var(--accent))] px-3 py-2 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] transition-colors"
        >
          <Plus className="h-4 w-4" /> Add Vendor
        </button>
      </div>

      <div className="flex flex-col gap-6">
        {Object.entries(groups).map(([cat, prov]) => (
          <div key={cat}>
            <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-[rgb(var(--text-muted))]">
              {catIcon[cat] ?? <Box className="h-4 w-4" />}
              {CATEGORIES.find(c => c.key === cat)?.label ?? cat}
              <span className="ml-1 rounded bg-[rgb(var(--border)/0.5)] px-1.5 py-0.5">{prov.length}</span>
            </div>
            <div className="grid grid-cols-4 gap-2">
              {prov.map(p => (
                <div key={p.key}
                  className="group flex items-center gap-2 rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-3 py-2.5 text-sm">
                  <span className="flex-1 truncate">{p.name}</span>
                  {!p.builtin && (
                    <button
                      onClick={() => handleDelete(p.key)}
                      className="hidden group-hover:flex text-[rgb(var(--text-muted))] hover:text-[rgb(var(--danger))] transition-colors"
                      title={`Remove ${p.name}`}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                  {!p.builtin && (
                    <span className="text-xs text-[rgb(var(--text-muted))] group-hover:hidden">custom</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {showAdd && (
        <AddProviderModal
          onClose={() => setShowAdd(false)}
          onSaved={load}
        />
      )}
    </div>
  )
}

function AddProviderModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState<AddProviderInput>({ key: '', name: '', category: 'custom' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const normalizeKey = (s: string) =>
    s.toLowerCase().replace(/[^a-z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!form.name) { setError('Name is required'); return }
    const key = form.key || normalizeKey(form.name)
    if (!key) { setError('Could not derive a key from the name'); return }
    setLoading(true)
    try {
      const res = await api.addProvider({ ...form, key })
      if (res.err) setError(res.err)
      else { onSaved(); onClose() }
    } catch (e: any) { setError(String(e)) }
    finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold">Add Custom Vendor</h2>
          <button onClick={onClose} className="text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))]">
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={submit} className="flex flex-col gap-3">
          <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
            Vendor Name <span className="text-[rgb(var(--danger))]">*</span>
            <input
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="e.g. Stripe, Twilio, SendGrid…"
              className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]"
            />
          </label>

          <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
            Key (auto-generated if blank)
            <input
              value={form.key}
              onChange={e => setForm(f => ({ ...f, key: e.target.value }))}
              placeholder={form.name ? normalizeKey(form.name) : 'e.g. stripe'}
              className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm font-mono text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]"
            />
          </label>

          <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
            Category
            <select
              value={form.category}
              onChange={e => setForm(f => ({ ...f, category: e.target.value }))}
              className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none"
            >
              {CATEGORIES.map(c => <option key={c.key} value={c.key}>{c.label}</option>)}
            </select>
          </label>

          {error && <p className="text-xs text-[rgb(var(--danger))]">{error}</p>}

          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose}
              className="flex-1 rounded-lg border border-[rgb(var(--border))] py-2.5 text-sm hover:bg-white/5">
              Cancel
            </button>
            <button type="submit" disabled={loading}
              className="flex-1 rounded-lg bg-[rgb(var(--accent))] py-2.5 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] disabled:opacity-50">
              {loading ? 'Saving…' : 'Add Vendor'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
