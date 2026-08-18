import { useEffect, useRef, useState } from 'react'
import { KeyRound, RefreshCw, Copy, Check, X } from 'lucide-react'
import { api } from '../api'
import StrengthBar from './StrengthBar'

type Opts = { lower: boolean; upper: boolean; num: boolean; sym: boolean }

// generate builds a random password from the selected character classes using the
// platform CSPRNG (Web Crypto) — never Math.random, and never any network call.
function generate(len: number, o: Opts): string {
  let chars = ''
  if (o.lower) chars += 'abcdefghijkmnpqrstuvwxyz'   // no l
  if (o.upper) chars += 'ABCDEFGHJKLMNPQRSTUVWXYZ'   // no I,O
  if (o.num) chars += '23456789'                     // no 0,1
  if (o.sym) chars += '!@#$%^&*()-_=+[]{};:,.?'
  if (!chars) chars = 'abcdefghijkmnpqrstuvwxyz'
  const buf = new Uint32Array(len)
  crypto.getRandomValues(buf)
  let out = ''
  for (let i = 0; i < len; i++) out += chars[buf[i] % chars.length]
  return out
}

// PasswordGenerator is a self-contained top-bar button + popover: it produces a strong
// random password the user can copy or optionally save as a new secret. Nothing leaves
// the machine.
export default function PasswordGenerator() {
  const [open, setOpen] = useState(false)
  const [len, setLen] = useState(20)
  const [opts, setOpts] = useState<Opts>({ lower: true, upper: true, num: true, sym: true })
  const [pw, setPw] = useState('')
  const [copied, setCopied] = useState(false)
  const [saving, setSaving] = useState(false)
  const [alias, setAlias] = useState('')
  const [saveMsg, setSaveMsg] = useState('')
  const ref = useRef<HTMLDivElement>(null)

  const regen = () => setPw(generate(len, opts))

  // Fresh password whenever the popover opens or the knobs change.
  useEffect(() => { if (open) setPw(generate(len, opts)) }, [open, len, opts])

  // Close on outside click / Escape.
  useEffect(() => {
    if (!open) return
    const onClick = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false) }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('mousedown', onClick); document.removeEventListener('keydown', onKey) }
  }, [open])

  async function copy() {
    await navigator.clipboard.writeText(pw)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
    setTimeout(async () => {
      try { if (await navigator.clipboard.readText() === pw) await navigator.clipboard.writeText('') } catch {}
    }, 30_000)
  }

  async function save() {
    if (!alias.trim()) { setSaveMsg('Enter an alias'); return }
    setSaving(true); setSaveMsg('')
    try {
      const res = await api.addSecret({ alias: alias.trim(), itemType: 'api_key', providerKey: 'custom', environment: 'dev', description: 'Generated password', value: pw })
      if (res.err) setSaveMsg(res.err)
      else { setSaveMsg('Saved'); setAlias(''); setTimeout(() => setSaveMsg(''), 1500) }
    } catch (e: any) { setSaveMsg(String(e)) }
    finally { setSaving(false) }
  }

  const toggle = (k: keyof Opts) => setOpts(o => ({ ...o, [k]: !o[k] }))
  const noDrag = { '--wails-draggable': 'no-drag' } as React.CSSProperties

  return (
    <div ref={ref} className="relative flex items-center" style={noDrag}>
      <button
        onClick={() => setOpen(o => !o)}
        title="Password generator"
        className="flex h-full items-center gap-1.5 px-3 text-xs text-[rgb(var(--text-muted))] hover:bg-white/10 hover:text-[rgb(var(--text))]"
      >
        <KeyRound className="h-3.5 w-3.5" /> Generate
      </button>

      {open && (
        <div className="absolute right-0 top-full z-50 mt-1 w-80 rounded-xl border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4 shadow-2xl" style={noDrag}>
          <div className="mb-3 flex items-center gap-2">
            <code className="flex-1 truncate rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-2 font-mono text-sm select-text">{pw}</code>
            <button onClick={regen} title="Regenerate" className="rounded-lg p-2 text-[rgb(var(--text-muted))] hover:bg-white/10 hover:text-[rgb(var(--text))]"><RefreshCw className="h-4 w-4" /></button>
            <button onClick={copy} title="Copy" className={`rounded-lg p-2 hover:bg-white/10 ${copied ? 'text-[rgb(var(--success))]' : 'text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))]'}`}>{copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}</button>
          </div>

          <StrengthBar value={pw} />

          <div className="mt-3 flex items-center gap-2 text-xs text-[rgb(var(--text-muted))]">
            <span className="w-14">Length</span>
            <input type="range" min={8} max={64} value={len} onChange={e => setLen(Number(e.target.value))} className="flex-1 accent-[rgb(var(--accent))]" />
            <span className="w-6 text-right font-mono text-[rgb(var(--text))]">{len}</span>
          </div>

          <div className="mt-2 grid grid-cols-2 gap-1.5 text-xs">
            {([['upper','A-Z'],['lower','a-z'],['num','0-9'],['sym','!@#']] as [keyof Opts,string][]).map(([k,label]) => (
              <label key={k} className="flex cursor-pointer items-center gap-2 text-[rgb(var(--text-muted))]">
                <input type="checkbox" checked={opts[k]} onChange={() => toggle(k)} className="accent-[rgb(var(--accent))]" /> {label}
              </label>
            ))}
          </div>

          <div className="mt-3 border-t border-[rgb(var(--border))] pt-3">
            <div className="flex items-center gap-2">
              <input value={alias} onChange={e => setAlias(e.target.value)} placeholder="Save as… (alias)"
                className="flex-1 rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-3 py-1.5 text-xs outline-none focus:border-[rgb(var(--accent))]" />
              <button onClick={save} disabled={saving}
                className="rounded-lg bg-[rgb(var(--accent))] px-3 py-1.5 text-xs font-medium text-white hover:bg-[rgb(var(--accent-hover))] disabled:opacity-50">
                {saving ? '…' : 'Save'}
              </button>
            </div>
            {saveMsg && <p className="mt-1.5 text-[10px] text-[rgb(var(--text-muted))]">{saveMsg}</p>}
            <p className="mt-1.5 text-[10px] text-[rgb(var(--text-muted))]">Optional — copy it, or store it as a secret. Your choice.</p>
          </div>

          <button onClick={() => setOpen(false)} className="absolute right-2 top-2 rounded p-1 text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))]"><X className="h-3.5 w-3.5" /></button>
        </div>
      )}
    </div>
  )
}
