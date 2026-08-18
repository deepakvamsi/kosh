import { useState, useEffect } from 'react'
import { api } from '../api'
import { Plus, Trash2, Check, X, ChevronDown, ChevronUp, Tag } from 'lucide-react'

type Field = { key: string; value: string }

function parseFields(raw: string): Field[] {
  try {
    const obj = JSON.parse(raw || '{}')
    return Object.entries(obj).map(([k, v]) => ({ key: k, value: String(v) }))
  } catch {
    return []
  }
}

function fieldsToJson(fields: Field[]): string {
  const obj: Record<string, string> = {}
  fields.forEach(f => { if (f.key.trim()) obj[f.key.trim()] = f.value })
  return JSON.stringify(obj)
}

type Props = {
  alias: string
  initialJson: string
  onSaved?: () => void
}

export default function CustomFieldsPanel({ alias, initialJson, onSaved }: Props) {
  const [open, setOpen] = useState(false)
  const [fields, setFields] = useState<Field[]>(() => parseFields(initialJson))
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    setFields(parseFields(initialJson))
  }, [initialJson])

  function addField() {
    setFields(f => [...f, { key: '', value: '' }])
  }

  function removeField(i: number) {
    setFields(f => f.filter((_, idx) => idx !== i))
  }

  function updateField(i: number, part: 'key' | 'value', val: string) {
    setFields(f => f.map((item, idx) => idx === i ? { ...item, [part]: val } : item))
  }

  async function save() {
    setSaving(true); setError('')
    try {
      const res = await api.setCustomFields(alias, fieldsToJson(fields))
      if (res.err) { setError(res.err) }
      else { setSaved(true); setTimeout(() => setSaved(false), 2000); onSaved?.() }
    } catch (e: any) { setError(String(e)) }
    finally { setSaving(false) }
  }

  const count = fields.filter(f => f.key.trim()).length

  return (
    <div className="border-t border-[rgb(var(--border)/0.4)]">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex w-full items-center gap-2 px-4 py-2 text-xs text-[rgb(var(--text-muted))] hover:text-[rgb(var(--text))] transition-colors"
      >
        <Tag className="h-3 w-3" />
        <span>Custom fields {count > 0 && <span className="rounded bg-[rgb(var(--accent)/0.15)] px-1.5 py-0.5 text-[rgb(var(--accent))]">{count}</span>}</span>
        {open ? <ChevronUp className="h-3 w-3 ml-auto" /> : <ChevronDown className="h-3 w-3 ml-auto" />}
      </button>

      {open && (
        <div className="px-4 pb-3 flex flex-col gap-2">
          {fields.length === 0 && (
            <p className="text-xs text-[rgb(var(--text-muted))] italic">No custom fields yet — click + to add one.</p>
          )}
          {fields.map((f, i) => (
            <div key={i} className="flex items-center gap-2">
              <input
                value={f.key}
                onChange={e => updateField(i, 'key', e.target.value)}
                placeholder="Field name (e.g. account_id)"
                className="w-36 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-2 py-1 text-xs text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))] select-text"
              />
              <span className="text-[rgb(var(--text-muted))]">:</span>
              <input
                value={f.value}
                onChange={e => updateField(i, 'value', e.target.value)}
                placeholder="Value"
                className="flex-1 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))] px-2 py-1 text-xs text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))] select-text"
              />
              <button onClick={() => removeField(i)} className="text-[rgb(var(--text-muted))] hover:text-[rgb(var(--danger))]">
                <Trash2 className="h-3 w-3" />
              </button>
            </div>
          ))}

          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={addField}
              className="flex items-center gap-1 rounded border border-[rgb(var(--border))] px-2 py-1 text-xs text-[rgb(var(--text-muted))] hover:bg-white/5"
            >
              <Plus className="h-3 w-3" /> Add field
            </button>
            <button
              onClick={save}
              disabled={saving}
              className={`flex items-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors disabled:opacity-50
                ${saved ? 'bg-green-500/15 text-green-400' : 'bg-[rgb(var(--accent)/0.15)] text-[rgb(var(--accent))] hover:bg-[rgb(var(--accent)/0.25)]'}`}
            >
              {saved ? <><Check className="h-3 w-3" /> Saved</> : saving ? 'Saving…' : <><Check className="h-3 w-3" /> Save</>}
            </button>
            {error && <span className="text-xs text-[rgb(var(--danger))]">{error}</span>}
          </div>
        </div>
      )}
    </div>
  )
}
