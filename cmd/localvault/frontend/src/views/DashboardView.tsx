import { useEffect, useState } from 'react'
import { api } from '../api'
import { HealthItem } from '../types'
import { Key, ShieldCheck, ShieldAlert, ShieldX, AlertTriangle } from 'lucide-react'

const flagLabel: Record<string, string> = {
  expired:       'Expired',
  expiring_soon: 'Expiring soon',
  unused:        'Unused (90+ days)',
  old:           'Old (180+ days)',
  duplicate:     'Duplicate',
}

const statusIcon = (s: string) => {
  if (s === 'healthy') return <ShieldCheck className="h-4 w-4 text-[rgb(var(--success))]" />
  if (s === 'warning') return <ShieldAlert className="h-4 w-4 text-[rgb(var(--warn))]" />
  return <ShieldX className="h-4 w-4 text-[rgb(var(--danger))]" />
}

export default function DashboardView({ onNav }: { onNav: (v: string) => void }) {
  const [total, setTotal] = useState(0)
  const [health, setHealth] = useState<HealthItem[]>([])
  const [version, setVersion] = useState('')

  useEffect(() => {
    api.listSecrets('', '', '', false).then(s => setTotal((s ?? []).length))
    api.getHealth().then(h => setHealth(h ?? []))
    api.getVersion().then(setVersion)
  }, [])

  const critical = health.filter(h => h.status === 'critical').length
  const warning  = health.filter(h => h.status === 'warning').length
  const healthy  = health.filter(h => h.status === 'healthy').length
  const needsAttention = health.filter(h => h.status !== 'healthy').sort((a, b) => a.score - b.score)

  const cards = [
    { label: 'Secrets',  value: total,    icon: <Key className="h-5 w-5" />,         color: 'rgb(var(--accent))' },
    { label: 'Critical', value: critical, icon: <ShieldX className="h-5 w-5" />,     color: 'rgb(var(--danger))' },
    { label: 'Warnings', value: warning,  icon: <ShieldAlert className="h-5 w-5" />, color: 'rgb(var(--warn))' },
    { label: 'Healthy',  value: healthy,  icon: <ShieldCheck className="h-5 w-5" />, color: 'rgb(var(--success))' },
  ]

  return (
    <div className="flex h-full flex-col gap-6 overflow-y-auto p-6">
      <div className="flex items-end justify-between">
        <h1 className="text-lg font-semibold">Dashboard</h1>
        <span className="text-xs text-[rgb(var(--text-muted))]">{version}</span>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {cards.map(({ label, value, icon, color }) => (
          <div key={label} className="flex flex-col gap-3 rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4">
            <div className="flex items-center justify-between">
              <span className="text-2xl font-bold" style={{ color }}>{value}</span>
              <span style={{ color }}>{icon}</span>
            </div>
            <p className="text-xs text-[rgb(var(--text-muted))]">{label}</p>
          </div>
        ))}
      </div>

      {/* Credential health, folded in from the old Token Health view. 100% local. */}
      <div className="rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-xs font-medium uppercase tracking-wider text-[rgb(var(--text-muted))]">Needs attention</h3>
          <button onClick={() => onNav('secrets')} className="text-xs text-[rgb(var(--accent))] hover:underline">All secrets →</button>
        </div>
        {needsAttention.length === 0 ? (
          <p className="text-sm text-[rgb(var(--text-muted))]">Everything looks healthy — nothing expiring, stale, or duplicated.</p>
        ) : (
          <div className="flex flex-col gap-2">
            {needsAttention.slice(0, 8).map(item => (
              <div key={item.secretId} className="flex items-center gap-3 rounded-lg border border-[rgb(var(--border)/0.6)] bg-[rgb(var(--bg)/0.4)] px-3 py-2">
                {statusIcon(item.status)}
                <span className="font-mono text-sm">{item.alias}</span>
                <div className="ml-auto flex flex-wrap items-center justify-end gap-1.5">
                  {item.flags.map(f => (
                    <span key={f} className="flex items-center gap-1 rounded bg-[rgb(var(--border)/0.5)] px-2 py-0.5 text-xs text-[rgb(var(--text-muted))]">
                      <AlertTriangle className="h-3 w-3 text-[rgb(var(--warn))]" />{flagLabel[f] ?? f}
                    </span>
                  ))}
                  {item.dupAliases.map(dup => (
                    <span key={dup} className="rounded bg-red-500/10 px-2 py-0.5 text-xs text-red-400">Dup: {dup}</span>
                  ))}
                </div>
              </div>
            ))}
            {needsAttention.length > 8 && (
              <p className="text-xs text-[rgb(var(--text-muted))]">+{needsAttention.length - 8} more</p>
            )}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4">
        <h3 className="mb-2 text-xs font-medium uppercase tracking-wider text-[rgb(var(--text-muted))]">Security posture</h3>
        <div className="flex flex-wrap gap-2">
          {['Air-sealed', 'No network', 'Screenshot-blocked', 'Local-only DB'].map(label => (
            <span key={label} className="flex items-center gap-1 rounded bg-green-500/10 px-2 py-1 text-xs text-green-400">✓ {label}</span>
          ))}
        </div>
      </div>
    </div>
  )
}
