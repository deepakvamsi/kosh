import { useState, useEffect } from 'react'
import { api } from '../api'
import { History, Eye, EyeOff, ChevronDown, ChevronUp } from 'lucide-react'

type Props = { alias: string }

export default function HistoryPanel({ alias }: Props) {
  const [open, setOpen]       = useState(false)
  const [entries, setEntries] = useState<{ id: number; changedAt: number }[]>([])
  const [revealed, setRevealed] = useState<Record<number, string>>({})
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!open) return
    api.listHistory(alias).then(e => setEntries(e ?? []))
  }, [open, alias])

  async function toggle(id: number) {
    if (revealed[id] !== undefined) {
      setRevealed(r => { const n = { ...r }; delete n[id]; return n })
      return
    }
    setLoading(true)
    try {
      const val = await api.revealHistoryValue(alias, id)
      setRevealed(r => ({ ...r, [id]: val }))
    } finally { setLoading(false) }
  }

  return (
    <div className="border-t border-[rgb(var(--border)/0.4)]">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex w-full items-center gap-2 px-4 py-2 text-xs text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))] transition-colors"
      >
        <History className="h-3 w-3" />
        Value history
        {open ? <ChevronUp className="h-3 w-3 ml-auto" /> : <ChevronDown className="h-3 w-3 ml-auto" />}
      </button>

      {open && (
        <div className="px-4 pb-3">
          {entries.length === 0 ? (
            <p className="text-xs text-[rgb(var(--text-muted))] italic">No previous values stored yet.</p>
          ) : (
            <div className="flex flex-col gap-1.5">
              {entries.map(e => (
                <div key={e.id} className="flex items-center gap-2">
                  <span className="w-36 shrink-0 text-xs text-[rgb(var(--text-muted))]">
                    {new Date(e.changedAt * 1000).toLocaleString()}
                  </span>
                  {revealed[e.id] !== undefined ? (
                    <code className="flex-1 truncate rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-2 py-1 font-mono text-xs text-[rgb(var(--text))] select-text">
                      {revealed[e.id]}
                    </code>
                  ) : (
                    <span className="flex-1 text-xs text-[rgb(var(--text-muted))] italic">hidden</span>
                  )}
                  <button onClick={() => toggle(e.id)} disabled={loading}
                    className="rounded p-1 text-[rgb(var(--text-muted))] hover:bg-white/10 hover:text-[rgb(var(--text))]">
                    {revealed[e.id] !== undefined
                      ? <EyeOff className="h-3.5 w-3.5" />
                      : <Eye className="h-3.5 w-3.5" />}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
