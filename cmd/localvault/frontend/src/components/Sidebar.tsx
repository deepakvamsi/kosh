import {
  LayoutDashboard, Key, ServerCog, Activity,
  ScrollText, HardDrive, Settings, Lock, FileSpreadsheet
} from 'lucide-react'
import Brandmark from './Brandmark'

export type View = 'dashboard' | 'secrets' | 'providers' | 'health' | 'audit' | 'backups' | 'import' | 'settings'

const items: { id: View; label: string; Icon: React.FC<{className?: string}> }[] = [
  { id: 'dashboard',  label: 'Dashboard',    Icon: LayoutDashboard },
  { id: 'secrets',    label: 'Secrets',       Icon: Key },
  { id: 'providers',  label: 'Providers',     Icon: ServerCog },
  { id: 'health',     label: 'Token Health',  Icon: Activity },
  { id: 'audit',      label: 'Audit Log',     Icon: ScrollText },
  { id: 'backups',    label: 'Backups',       Icon: HardDrive },
  { id: 'import',     label: 'Import',        Icon: FileSpreadsheet },
  { id: 'settings',   label: 'Settings',      Icon: Settings },
]

type Props = {
  current: View
  onChange: (v: View) => void
  onLock: () => void
}

export default function Sidebar({ current, onChange, onLock }: Props) {
  return (
    <aside className="flex h-screen w-52 shrink-0 flex-col border-r border-[rgb(var(--border))] bg-[rgb(var(--surface))]">
      <div className="flex items-center gap-2 px-4 py-4 border-b border-[rgb(var(--border))]">
        <Brandmark className="h-7 w-7 shrink-0 text-[rgb(var(--accent))]" />
        <span className="text-sm font-semibold truncate">Kosh</span>
      </div>

      <nav className="flex-1 overflow-y-auto py-2">
        {items.map(({ id, label, Icon }) => (
          <button
            key={id}
            onClick={() => onChange(id)}
            className={`flex w-full items-center gap-3 px-4 py-2.5 text-sm transition-colors
              ${current === id
                ? 'bg-[rgb(var(--accent)/0.15)] text-[rgb(var(--accent))] font-medium'
                : 'text-[rgb(var(--text-muted))] hover:bg-white/5 hover:text-[rgb(var(--text))]'}`}
          >
            <Icon className="h-4 w-4 shrink-0" />
            {label}
          </button>
        ))}
      </nav>

      <div className="border-t border-[rgb(var(--border))] p-2">
        <button
          onClick={onLock}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm text-[rgb(var(--text-muted))] hover:bg-white/5 hover:text-[rgb(var(--danger))] transition-colors"
        >
          <Lock className="h-4 w-4" />
          Lock Vault
        </button>
      </div>
    </aside>
  )
}
