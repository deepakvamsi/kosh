import { useEffect, useState } from 'react'
import { api } from '../api'
import { HealthItem, SecretSummary } from '../types'
import { Key, Activity, ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react'
import Brandmark from '../components/Brandmark'

export default function DashboardView({ onNav }: { onNav: (v: string) => void }) {
  const [total, setTotal] = useState(0)
  const [health, setHealth] = useState<HealthItem[]>([])
  const [version, setVersion] = useState('')

  useEffect(() => {
    api.listSecrets('','','',false).then(s => setTotal((s ?? []).length))
    api.getHealth().then(h => setHealth(h ?? []))
    api.getVersion().then(setVersion)
  }, [])

  const critical = health.filter(h => h.status === 'critical').length
  const warning  = health.filter(h => h.status === 'warning').length
  const healthy  = health.filter(h => h.status === 'healthy').length

  const cards = [
    { label: 'Total Secrets',  value: total,    icon: <Key      className="h-5 w-5" />, color: 'rgb(var(--accent))' },
    { label: 'Critical',       value: critical, icon: <ShieldX  className="h-5 w-5" />, color: 'rgb(var(--danger))' },
    { label: 'Warnings',       value: warning,  icon: <ShieldAlert className="h-5 w-5" />, color: 'rgb(var(--warn))' },
    { label: 'Healthy',        value: healthy,  icon: <ShieldCheck className="h-5 w-5" />, color: 'rgb(var(--success))' },
  ]

  return (
    <div className="flex h-full flex-col gap-6 overflow-y-auto p-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-lg font-semibold">Dashboard</h1>
          <p className="text-xs text-[rgb(var(--text-muted))]">{version}</p>
        </div>
        <Brandmark className="h-8 w-8 text-[rgb(var(--text-muted))] opacity-70" />
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        {cards.map(({ label, value, icon, color }) => (
          <div key={label}
            className="flex flex-col gap-3 rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4">
            <div className="flex items-center justify-between">
              <span className="text-2xl font-bold" style={{ color }}>{value}</span>
              <span style={{ color }}>{icon}</span>
            </div>
            <p className="text-xs text-[rgb(var(--text-muted))]">{label}</p>
          </div>
        ))}
      </div>

      {critical > 0 && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4">
          <p className="mb-2 text-sm font-medium text-red-400">Action needed</p>
          <ul className="space-y-1 text-xs text-[rgb(var(--text-muted))]">
            {health.filter(h => h.status === 'critical').slice(0,5).map(h => (
              <li key={h.secretId}>
                <span className="font-mono text-[rgb(var(--text))]">{h.alias}</span>
                {' — '}{h.flags.join(', ')}
              </li>
            ))}
          </ul>
          <button onClick={() => onNav('health')}
            className="mt-3 text-xs text-[rgb(var(--accent))] hover:underline">
            View Token Health →
          </button>
        </div>
      )}

      <div className="rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4">
        <h3 className="mb-2 text-xs font-medium text-[rgb(var(--text-muted))] uppercase tracking-wider">Security posture</h3>
        <div className="flex gap-2">
          {[
            { label: 'Air-sealed', ok: true },
            { label: 'No network',  ok: true },
            { label: 'Screenshot-blocked', ok: true },
            { label: 'Local-only DB', ok: true },
          ].map(({ label, ok }) => (
            <span key={label}
              className={`flex items-center gap-1 rounded px-2 py-1 text-xs ${ok ? 'bg-green-500/10 text-green-400' : 'bg-red-500/10 text-red-400'}`}>
              {ok ? '✓' : '✗'} {label}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}
