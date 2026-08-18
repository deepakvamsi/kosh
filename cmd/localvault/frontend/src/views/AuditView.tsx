import { useCallback, useEffect, useState } from 'react'
import { api } from '../api'
import { AuditEntry } from '../types'
import { CheckCircle, XCircle, ShieldCheck, ShieldAlert, RefreshCw, Filter } from 'lucide-react'

type ChainState = 'unchecked' | 'ok' | 'broken'

export default function AuditView() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [chain, setChain] = useState<ChainState>('unchecked')
  const [badSeq, setBadSeq] = useState<number>(0)
  const [checking, setChecking] = useState(false)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [outcomeFilter, setOutcomeFilter] = useState<'all' | 'allow' | 'deny'>('all')

  const load = useCallback(async () => {
    setLoading(true)
    const d = await api.getAuditLog(500)
    setEntries(d ?? [])
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])

  async function verifyChain() {
    setChecking(true)
    try {
      const bad = await api.verifyChain()
      setBadSeq(bad)
      setChain(bad === 0 ? 'ok' : 'broken')
    } finally {
      setChecking(false)
    }
  }

  const visible = entries.filter(e => {
    if (outcomeFilter !== 'all' && e.outcome !== outcomeFilter) return false
    if (!filter) return true
    const q = filter.toLowerCase()
    return e.action.toLowerCase().includes(q) ||
           (e.target || '').toLowerCase().includes(q) ||
           (e.detail || '').toLowerCase().includes(q)
  })

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b border-[rgb(var(--border))] px-6 py-4">
        <h2 className="text-sm font-semibold">Audit Log</h2>

        <div className="flex-1" />

        <div className="flex items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-[rgb(var(--text-muted))]" />
          <input
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter by action / target…"
            className="rounded border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-2 py-1 text-xs outline-none focus:border-[rgb(var(--accent))]"
          />
          <select
            value={outcomeFilter}
            onChange={e => setOutcomeFilter(e.target.value as any)}
            className="rounded border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-2 py-1 text-xs outline-none"
          >
            <option value="all">All outcomes</option>
            <option value="allow">Allow only</option>
            <option value="deny">Deny only</option>
          </select>
        </div>

        <button
          onClick={verifyChain}
          disabled={checking}
          className="flex items-center gap-1.5 rounded-lg border border-[rgb(var(--border))] px-3 py-1.5 text-xs hover:bg-white/5 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${checking ? 'animate-spin' : ''}`} />
          Verify chain
        </button>

        {chain !== 'unchecked' && (
          <div className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium
            ${chain === 'ok'
              ? 'bg-green-500/10 text-[rgb(var(--success))]'
              : 'bg-red-500/10 text-[rgb(var(--danger))]'}`}
          >
            {chain === 'ok'
              ? <><ShieldCheck className="h-3.5 w-3.5" /> Chain intact ({entries.length} records)</>
              : <><ShieldAlert className="h-3.5 w-3.5" /> BROKEN at seq {badSeq} — tamper detected!</>}
          </div>
        )}
      </div>

      {chain === 'broken' && (
        <div className="border-b border-red-500/30 bg-red-500/5 px-6 py-3 text-xs text-red-400">
          The audit chain is broken at sequence {badSeq}. A record has been deleted or modified.
          This is a security violation. Do not trust log entries at or after seq {badSeq}.
          Take a backup and investigate before continuing.
        </div>
      )}

      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="flex h-full items-center justify-center text-xs text-[rgb(var(--text-muted))]">Loading…</div>
        ) : visible.length === 0 ? (
          <div className="flex h-full items-center justify-center text-xs text-[rgb(var(--text-muted))]">No entries match</div>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-[rgb(var(--surface))] text-[rgb(var(--text-muted))] uppercase tracking-wider">
              <tr>
                {['Seq','Time','Action','Target','Outcome','Detail'].map(h => (
                  <th key={h} className="px-4 py-3 text-left font-medium border-b border-[rgb(var(--border))]">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.map(e => (
                <tr
                  key={e.seq}
                  className={`border-b border-[rgb(var(--border)/0.3)] hover:bg-white/3
                    ${chain === 'broken' && e.seq >= badSeq ? 'opacity-50' : ''}`}
                >
                  <td className="px-4 py-2 text-[rgb(var(--text-muted))]">{e.seq}</td>
                  <td className="px-4 py-2 text-[rgb(var(--text-muted))] whitespace-nowrap">
                    {new Date(e.ts * 1000).toLocaleString()}
                  </td>
                  <td className="px-4 py-2 font-medium">{e.action}</td>
                  <td className="px-4 py-2 font-mono">{e.target || '—'}</td>
                  <td className="px-4 py-2">
                    {e.outcome === 'allow'
                      ? <CheckCircle className="h-3.5 w-3.5 text-[rgb(var(--success))]" />
                      : <XCircle    className="h-3.5 w-3.5 text-[rgb(var(--danger))]" />}
                  </td>
                  <td className="px-4 py-2 text-[rgb(var(--text-muted))]">{e.detail || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="border-t border-[rgb(var(--border))] px-6 py-2 text-xs text-[rgb(var(--text-muted))]">
        {visible.length} of {entries.length} entries
        {chain === 'unchecked' && <span className="ml-3 italic">Chain not yet verified — click "Verify chain" to check tamper-evidence.</span>}
      </div>
    </div>
  )
}
