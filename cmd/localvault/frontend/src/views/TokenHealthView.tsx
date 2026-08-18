import { useEffect, useState } from 'react'
import { api } from '../api'
import { HealthItem } from '../types'
import { ShieldCheck, ShieldAlert, ShieldX, AlertTriangle } from 'lucide-react'

const statusIcon = (s: string) => {
  if (s === 'healthy')  return <ShieldCheck className="h-4 w-4 text-[rgb(var(--success))]" />
  if (s === 'warning')  return <ShieldAlert  className="h-4 w-4 text-[rgb(var(--warn))]" />
  return                       <ShieldX      className="h-4 w-4 text-[rgb(var(--danger))]" />
}

const flagLabel: Record<string, string> = {
  expired:        'Expired',
  expiring_soon:  'Expiring soon',
  unused:         'Unused (90+ days)',
  old:            'Old (180+ days)',
  duplicate:      'Duplicate credential',
}

export default function TokenHealthView() {
  const [items, setItems] = useState<HealthItem[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getHealth().then(d => { setItems(d ?? []); setLoading(false) })
  }, [])

  const critical = items.filter(i => i.status === 'critical').length
  const warning  = items.filter(i => i.status === 'warning').length
  const healthy  = items.filter(i => i.status === 'healthy').length

  return (
    <div className="flex h-full flex-col gap-6 overflow-y-auto p-6">
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Critical',  count: critical, color: 'rgb(var(--danger))'  },
          { label: 'Warning',   count: warning,  color: 'rgb(var(--warn))'    },
          { label: 'Healthy',   count: healthy,  color: 'rgb(var(--success))' },
        ].map(({ label, count, color }) => (
          <div key={label} className="rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4">
            <p className="text-2xl font-bold" style={{ color }}>{count}</p>
            <p className="text-xs text-[rgb(var(--text-muted))]">{label}</p>
          </div>
        ))}
      </div>

      {loading ? (
        <p className="text-sm text-[rgb(var(--text-muted))]">Loading…</p>
      ) : items.length === 0 ? (
        <p className="text-sm text-[rgb(var(--text-muted))]">No secrets to analyse.</p>
      ) : (
        <div className="flex flex-col gap-2">
          {items
            .sort((a, b) => a.score - b.score)
            .map(item => (
            <div key={item.secretId}
              className="flex items-start gap-4 rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-4 py-3">
              <div className="mt-0.5">{statusIcon(item.status)}</div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-medium">{item.alias}</span>
                  <span className="ml-auto text-xs text-[rgb(var(--text-muted))]">Score {item.score}/100</span>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {item.flags.map(f => (
                    <span key={f}
                      className="flex items-center gap-1 rounded bg-[rgb(var(--border)/0.5)] px-2 py-0.5 text-xs">
                      <AlertTriangle className="h-3 w-3 text-[rgb(var(--warn))]" />
                      {flagLabel[f] ?? f}
                    </span>
                  ))}
                  {item.dupAliases.map(dup => (
                    <span key={dup} className="rounded bg-red-500/10 px-2 py-0.5 text-xs text-red-400">
                      Dup: {dup}
                    </span>
                  ))}
                </div>
              </div>
              <div className="flex items-center">
                <div className="h-2 w-24 overflow-hidden rounded-full bg-[rgb(var(--border))]">
                  <div
                    className="h-2 rounded-full"
                    style={{
                      width: `${item.score}%`,
                      backgroundColor: item.score >= 80 ? 'rgb(var(--success))' : item.score >= 40 ? 'rgb(var(--warn))' : 'rgb(var(--danger))',
                    }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
