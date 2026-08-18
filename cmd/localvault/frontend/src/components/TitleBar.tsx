import { Minus, Square, X } from 'lucide-react'
import { WindowMinimise, WindowToggleMaximise, Quit } from '../../wailsjs/runtime/runtime'
import Brandmark from './Brandmark'
import PasswordGenerator from './PasswordGenerator'

// TitleBar is the custom window chrome for the frameless window: a draggable strip with
// the brand, the global password generator, and minimize / maximize / close controls.
export default function TitleBar() {
  const drag = { '--wails-draggable': 'drag' } as React.CSSProperties
  const noDrag = { '--wails-draggable': 'no-drag' } as React.CSSProperties

  return (
    <div className="flex h-9 shrink-0 select-none items-center justify-between border-b border-[rgb(var(--border))] bg-[rgb(var(--surface))]" style={drag}>
      <div className="flex items-center gap-2 px-3 text-xs text-[rgb(var(--text-muted))]">
        <Brandmark className="h-4 w-4 text-[rgb(var(--accent))]" />
        <span className="font-semibold text-[rgb(var(--text))]">Kosh</span>
      </div>

      <div className="flex h-full items-stretch" style={noDrag}>
        <PasswordGenerator />
        <button onClick={() => WindowMinimise()} title="Minimize"
          className="flex w-11 items-center justify-center text-[rgb(var(--text-muted))] hover:bg-white/10 hover:text-[rgb(var(--text))]">
          <Minus className="h-3.5 w-3.5" />
        </button>
        <button onClick={() => WindowToggleMaximise()} title="Maximize"
          className="flex w-11 items-center justify-center text-[rgb(var(--text-muted))] hover:bg-white/10 hover:text-[rgb(var(--text))]">
          <Square className="h-3 w-3" />
        </button>
        <button onClick={() => Quit()} title="Close"
          className="flex w-11 items-center justify-center text-[rgb(var(--text-muted))] hover:bg-red-600 hover:text-white">
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}
