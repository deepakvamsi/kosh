import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import { SecretSummary, AddSecretInput, AddKeyPairInput, Provider } from '../types'
import { Plus, Search, Eye, EyeOff, Copy, Trash2, Archive, RotateCcw, KeyRound, Link2 } from 'lucide-react'
import CustomFieldsPanel from '../components/CustomFieldsPanel'

type RevealState = { alias: string; value: string; timer: ReturnType<typeof setTimeout> | null }
type AddMode = 'single' | 'keypair'

export default function SecretsView() {
  const [secrets, setSecrets] = useState<SecretSummary[]>([])
  const [providers, setProviders] = useState<Provider[]>([])
  const [search, setSearch] = useState('')
  const [filterEnv, setFilterEnv] = useState('')
  const [filterProv, setFilterProv] = useState('')
  const [includeArchived, setIncludeArchived] = useState(false)
  const [revealed, setRevealed] = useState<RevealState | null>(null)
  const [addMode, setAddMode] = useState<AddMode | null>(null)
  const [copied, setCopied] = useState('')

  const load = useCallback(async () => {
    const [s, p] = await Promise.all([
      api.listSecrets(search, filterProv, filterEnv, includeArchived),
      api.listProviders(),
    ])
    setSecrets(s ?? [])
    setProviders(p ?? [])
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
      const value = await api.revealSecret(alias)
      const timer = setTimeout(() => setRevealed(null), 30_000)
      setRevealed({ alias, value, timer })
    } catch (e: any) { alert('Reveal failed: ' + e) }
  }

  async function handleCopy(alias: string) {
    const value = revealed?.alias === alias ? revealed.value : await api.revealSecret(alias)
    await navigator.clipboard.writeText(value)
    setCopied(alias)
    setTimeout(() => setCopied(''), 2000)
    setTimeout(async () => {
      try { const cur = await navigator.clipboard.readText(); if (cur === value) await navigator.clipboard.writeText('') } catch {}
    }, 30_000)
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

  const isPairedAlias = (alias: string) =>
    secrets.some(s => s !== secrets.find(x => x.alias === alias) &&
      (alias.endsWith('_ACCESS_KEY') && s.alias === alias.replace('_ACCESS_KEY', '_SECRET_KEY') ||
       alias.endsWith('_SECRET_KEY') && s.alias === alias.replace('_SECRET_KEY', '_ACCESS_KEY')))

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-[rgb(var(--border))] px-6 py-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[rgb(var(--text-muted))]" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by alias or description…"
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

        <div className="flex items-center gap-2">
          <button onClick={() => setAddMode('single')}
            className="flex items-center gap-2 rounded-lg bg-[rgb(var(--accent))] px-3 py-2 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] transition-colors">
            <Plus className="h-4 w-4" /> Add Secret
          </button>
          <button onClick={() => setAddMode('keypair')}
            title="Add Access Key + Secret Key pair (AWS-style)"
            className="flex items-center gap-2 rounded-lg border border-[rgb(var(--accent)/0.5)] px-3 py-2 text-sm font-medium text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent)/0.08)] transition-colors">
            <KeyRound className="h-4 w-4" /> Key Pair
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {secrets.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-4 text-sm text-[rgb(var(--text-muted))]">
            <KeyRound className="h-10 w-10 opacity-20" />
            <div className="text-center">
              <p className="font-medium">No secrets yet</p>
              <p className="text-xs mt-1">Use "Add Secret" for a single key, or "Key Pair" for Access Key + Secret Key (AWS, etc.)</p>
            </div>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-[rgb(var(--surface))] text-xs text-[rgb(var(--text-muted))] uppercase tracking-wider">
              <tr>
                {['Alias','Provider','Env','Tags','Expires',''].map(h => (
                  <th key={h} className="px-4 py-3 text-left font-medium border-b border-[rgb(var(--border))]">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {secrets.map(s => (
                <>
                  <tr key={s.id}
                    className={`border-b border-[rgb(var(--border)/0.5)] hover:bg-white/3 transition-colors ${s.isArchived ? 'opacity-50' : ''}`}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        {isPairedAlias(s.alias) && (
                          <span title="Part of a key pair">
                            <Link2 className="h-3 w-3 text-[rgb(var(--accent)/0.6)] shrink-0" />
                          </span>
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
                        {s.tags.map(t => (
                          <span key={t} className="rounded bg-[rgb(var(--border)/0.6)] px-1.5 py-0.5 text-xs text-[rgb(var(--text-muted))]">{t}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-[rgb(var(--text-muted))]">
                      {s.expiresAt ? new Date(s.expiresAt * 1000).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5 justify-end">
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
                    <tr key={`${s.id}-reveal`} className="bg-[rgb(var(--accent)/0.05)]">
                      <td colSpan={6} className="px-4 py-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-[rgb(var(--text-muted))]">Value:</span>
                          <code className="flex-1 rounded bg-[rgb(var(--surface))] px-3 py-1.5 font-mono text-xs text-[rgb(var(--text))] select-text border border-[rgb(var(--border))]">
                            {revealed.value}
                          </code>
                          <span className="text-xs text-[rgb(var(--text-muted))]">Auto-hides in 30s</span>
                        </div>
                        <CustomFieldsPanel
                          alias={s.alias}
                          initialJson={s.customFields}
                          onSaved={load}
                        />
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {addMode === 'single' && (
        <AddSecretModal providers={providers} onClose={() => setAddMode(null)} onSaved={load} />
      )}
      {addMode === 'keypair' && (
        <AddKeyPairModal providers={providers} onClose={() => setAddMode(null)} onSaved={load} />
      )}
    </div>
  )
}

function AddSecretModal({ providers, onClose, onSaved }: { providers: Provider[]; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState<AddSecretInput>({ alias: '', providerKey: providers[0]?.key ?? 'openai', environment: 'dev', description: '', value: '' })
  const [showVal, setShowVal] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!form.alias || !form.value) { setError('Alias and value are required'); return }
    setLoading(true)
    try {
      const res = await api.addSecret(form)
      if (res.err) setError(res.err)
      else { onSaved(); onClose() }
    } catch (e: any) { setError(String(e)) }
    finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-6 shadow-2xl">
        <h2 className="mb-4 text-base font-semibold">Add Single Secret</h2>
        <form onSubmit={submit} className="flex flex-col gap-3">
          {[
            { label: 'Alias', key: 'alias', placeholder: 'MY_API_KEY' },
            { label: 'Description', key: 'description', placeholder: 'Optional' },
          ].map(({ label, key, placeholder }) => (
            <label key={key} className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
              {label}
              <input value={(form as any)[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                placeholder={placeholder}
                className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]" />
            </label>
          ))}
          <div className="grid grid-cols-2 gap-3">
            <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
              Provider
              <select value={form.providerKey} onChange={e => setForm(f => ({ ...f, providerKey: e.target.value }))}
                className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none">
                {providers.map(p => <option key={p.key} value={p.key}>{p.name}</option>)}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
              Environment
              <select value={form.environment} onChange={e => setForm(f => ({ ...f, environment: e.target.value }))}
                className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none">
                {['dev','qa','staging','prod'].map(v => <option key={v} value={v}>{v}</option>)}
              </select>
            </label>
          </div>
          <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
            Secret Value
            <div className="relative">
              <input type={showVal ? 'text' : 'password'} value={form.value}
                onChange={e => setForm(f => ({ ...f, value: e.target.value }))} placeholder="sk-…"
                className="w-full rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 pr-10 text-sm text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]" />
              <button type="button" onClick={() => setShowVal(v => !v)} className="absolute right-2 top-1/2 -translate-y-1/2 text-[rgb(var(--text-muted))]">
                {showVal ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
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

function AddKeyPairModal({ providers, onClose, onSaved }: { providers: Provider[]; onClose: () => void; onSaved: () => void }) {
  const [providerKey, setProviderKey] = useState(providers.find(p => p.key === 'aws')?.key ?? providers[0]?.key ?? 'aws')
  const [service, setService]         = useState('')
  const [env, setEnv]                 = useState('dev')
  const [description, setDescription] = useState('')
  const [accessKey, setAccessKey]     = useState('')
  const [secretKey, setSecretKey]     = useState('')
  const [showAK, setShowAK]           = useState(false)
  const [showSK, setShowSK]           = useState(false)
  const [error, setError]             = useState('')
  const [loading, setLoading]         = useState(false)

  const normalize = (s: string) => s.toUpperCase().replace(/[^A-Z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '')
  const prov   = normalize(providers.find(p => p.key === providerKey)?.name ?? providerKey)
  const svc    = normalize(service)
  const envUp  = env.toUpperCase()

  const baseName    = [prov, svc, envUp].filter(Boolean).join('_')
  const accessAlias = baseName ? `${baseName}_ACCESS_KEY` : 'PROVIDER_SERVICE_ENV_ACCESS_KEY'
  const secretAlias = baseName ? `${baseName}_SECRET_KEY` : 'PROVIDER_SERVICE_ENV_SECRET_KEY'

  const serviceSuggestions: Record<string, string[]> = {
    aws:       ['IAM', 'Bedrock', 'S3', 'Lambda', 'DynamoDB', 'EC2', 'SQS', 'Console', 'CodeDeploy', 'CloudWatch'],
    gcp:       ['Vertex AI', 'BigQuery', 'Cloud Storage', 'Cloud Run', 'Pub Sub', 'GKE'],
    azure:     ['OpenAI', 'Blob Storage', 'Functions', 'Service Bus', 'AKS'],
    anthropic: ['API', 'Claude'],
    openai:    ['API', 'Fine Tuning', 'Assistants'],
    github:    ['Actions', 'Packages', 'CLI', 'Deploy'],
  }
  const suggestions = serviceSuggestions[providerKey] ?? []

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!service)   { setError('Service / purpose is required (e.g. Bedrock, IAM, Console)'); return }
    if (!accessKey) { setError('Access key value is required'); return }
    if (!secretKey) { setError('Secret key value is required'); return }

    const input: AddKeyPairInput = {
      accessKeyAlias: accessAlias,
      accessKeyValue: accessKey,
      secretKeyAlias: secretAlias,
      secretKeyValue: secretKey,
      providerKey,
      environment: env,
      description: description || `${providers.find(p => p.key === providerKey)?.name ?? providerKey} ${service} ${env}`,
    }

    setLoading(true)
    try {
      const res = await api.addKeyPair(input)
      if (res.err) setError(res.err)
      else { onSaved(); onClose() }
    } catch (e: any) { setError(String(e)) }
    finally { setLoading(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-6 shadow-2xl">
        <div className="mb-4 flex items-center gap-2">
          <KeyRound className="h-5 w-5 text-[rgb(var(--accent))]" />
          <h2 className="text-base font-semibold">Add Key Pair</h2>
          <span className="ml-auto text-xs text-[rgb(var(--text-muted))]">Both keys encrypted separately, linked by name</span>
        </div>

        <form onSubmit={submit} className="flex flex-col gap-3">
          <div className="grid grid-cols-3 gap-3">
            <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
              Provider
              <select value={providerKey} onChange={e => { setProviderKey(e.target.value); setService('') }}
                className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none">
                {providers.map(p => <option key={p.key} value={p.key}>{p.name}</option>)}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
              Service / Purpose <span className="text-[rgb(var(--danger))]">*</span>
              <input value={service} onChange={e => setService(e.target.value)}
                list="svc-suggestions"
                placeholder="e.g. Bedrock, IAM, S3…"
                className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]" />
              <datalist id="svc-suggestions">
                {suggestions.map(s => <option key={s} value={s} />)}
              </datalist>
            </label>
            <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
              Environment
              <select value={env} onChange={e => setEnv(e.target.value)}
                className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none">
                {['dev','qa','staging','prod'].map(v => <option key={v} value={v}>{v}</option>)}
              </select>
            </label>
          </div>

          <div className="rounded-lg border border-[rgb(var(--border)/0.4)] bg-[rgb(var(--bg)/0.5)] p-3">
            <p className="mb-1.5 text-xs font-medium text-[rgb(var(--text-muted))] uppercase tracking-wider">Aliases that will be created</p>
            <div className="flex gap-2">
              <code className="flex-1 rounded bg-[rgb(var(--accent)/0.1)] px-2.5 py-1.5 text-xs font-mono text-[rgb(var(--accent))] truncate">{accessAlias}</code>
              <code className="flex-1 rounded bg-[rgb(var(--accent)/0.1)] px-2.5 py-1.5 text-xs font-mono text-[rgb(var(--accent))] truncate">{secretAlias}</code>
            </div>
          </div>

          <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
            Description <span className="text-[10px]">(optional)</span>
            <input value={description} onChange={e => setDescription(e.target.value)}
              placeholder="Leave blank to auto-generate from provider + service + env"
              className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 text-sm text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]" />
          </label>

          <div className="grid grid-cols-2 gap-3">
            <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
              Access Key <span className="text-[rgb(var(--danger))]">*</span>
              <div className="relative">
                <input type={showAK ? 'text' : 'password'} value={accessKey} onChange={e => setAccessKey(e.target.value)}
                  placeholder="AKIA… / key ID"
                  className="w-full rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 pr-9 text-sm font-mono text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]" />
                <button type="button" onClick={() => setShowAK(v => !v)} className="absolute right-2 top-1/2 -translate-y-1/2 text-[rgb(var(--text-muted))]">
                  {showAK ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </label>
            <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
              Secret Key <span className="text-[rgb(var(--danger))]">*</span>
              <div className="relative">
                <input type={showSK ? 'text' : 'password'} value={secretKey} onChange={e => setSecretKey(e.target.value)}
                  placeholder="wJal… / secret"
                  className="w-full rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 pr-9 text-sm font-mono text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]" />
                <button type="button" onClick={() => setShowSK(v => !v)} className="absolute right-2 top-1/2 -translate-y-1/2 text-[rgb(var(--text-muted))]">
                  {showSK ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </label>
          </div>

          {error && <p className="text-xs text-[rgb(var(--danger))]">{error}</p>}

          <div className="flex gap-2 pt-1">
            <button type="button" onClick={onClose}
              className="flex-1 rounded-lg border border-[rgb(var(--border))] py-2.5 text-sm hover:bg-white/5">
              Cancel
            </button>
            <button type="submit" disabled={loading}
              className="flex-1 rounded-lg bg-[rgb(var(--accent))] py-2.5 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] disabled:opacity-50">
              {loading ? 'Saving…' : 'Save Both Keys'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
