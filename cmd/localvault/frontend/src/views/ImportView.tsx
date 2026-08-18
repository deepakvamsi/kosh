import { useState, useCallback } from 'react'
import { api } from '../api'
import { ImportPreviewResult, ImportRowDTO, ColMapDTO } from '../types'
import { FileSpreadsheet, CheckCircle, XCircle, AlertTriangle, Upload, Trash2, Info } from 'lucide-react'

const DEFAULT_CM: ColMapDTO = { alias: -1, value: -1, providerKey: -1, environment: -1, description: -1, expiresAt: -1 }

const statusBadge = (s: ImportRowDTO['status']) => {
  switch (s) {
    case 'pending':   return <span className="rounded bg-blue-500/15 px-1.5 py-0.5 text-xs text-blue-400">pending</span>
    case 'imported':  return <span className="rounded bg-green-500/15 px-1.5 py-0.5 text-xs text-green-400">imported</span>
    case 'duplicate': return <span className="rounded bg-yellow-500/15 px-1.5 py-0.5 text-xs text-yellow-400">duplicate</span>
    case 'invalid':   return <span className="rounded bg-red-500/15 px-1.5 py-0.5 text-xs text-red-400">invalid</span>
    case 'skipped':   return <span className="rounded bg-[rgb(var(--border)/0.5)] px-1.5 py-0.5 text-xs text-[rgb(var(--text-muted))]">skipped</span>
    default: return null
  }
}

const envBadge = (e: string) => {
  const map: Record<string, string> = { prod:'bg-red-500/15 text-red-400', staging:'bg-orange-500/15 text-orange-400', qa:'bg-yellow-500/15 text-yellow-400', dev:'bg-green-500/15 text-green-400' }
  return map[e] ?? 'bg-[rgb(var(--border)/0.5)] text-[rgb(var(--text-muted))]'
}

type Step = 'pick' | 'map' | 'preview' | 'done'

export default function ImportView() {
  const [step, setStep] = useState<Step>('pick')
  const [filePath, setFilePath] = useState('')
  const [preview, setPreview] = useState<ImportPreviewResult | null>(null)
  const [cm, setCm] = useState<ColMapDTO>(DEFAULT_CM)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<{ imported: number; invalid: number; errors: string[] } | null>(null)

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    setFilePath((file as any).path ?? file.name)
    setStep('map')
    setPreview(null)
    setCm(DEFAULT_CM)
    setError('')
  }

  const handlePreview = useCallback(async () => {
    if (!filePath) return
    setLoading(true); setError('')
    try {
      const p = await api.importPreview(filePath, cm)
      setPreview(p)
      if (cm.alias < 0) setCm(p.colMap)
      setStep('preview')
    } catch (e: any) { setError(String(e)) }
    finally { setLoading(false) }
  }, [filePath, cm])

  async function handleCommit() {
    if (!filePath) return
    setLoading(true); setError('')
    try {
      const res = await api.importCommit(filePath, cm)
      setResult({ imported: res.imported, invalid: res.invalid, errors: res.errors })
      setStep('done')
    } catch (e: any) { setError(String(e)) }
    finally { setLoading(false) }
  }

  function reset() {
    setStep('pick'); setFilePath(''); setPreview(null)
    setCm(DEFAULT_CM); setResult(null); setError('')
  }

  const pending = preview?.rows.filter(r => r.status === 'pending').length ?? 0
  const invalid = preview?.rows.filter(r => r.status === 'invalid').length ?? 0

  return (
    <div className="flex h-full flex-col overflow-y-auto p-6 gap-6">
      <div className="flex items-center gap-3">
        <FileSpreadsheet className="h-5 w-5 text-[rgb(var(--accent))]" />
        <h2 className="text-sm font-semibold">Import from Excel / CSV</h2>
      </div>

      <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 p-4 text-xs text-blue-300 flex gap-2">
        <Info className="h-4 w-4 mt-0.5 shrink-0" />
        <div>
          All parsing and encryption happen locally. After a successful import, please
          <strong> delete your source spreadsheet</strong> — it contains plaintext credentials.
        </div>
      </div>

      {step === 'pick' && (
        <label className="flex cursor-pointer flex-col items-center justify-center gap-4 rounded-xl border-2 border-dashed border-[rgb(var(--border))] p-12 hover:border-[rgb(var(--accent))/0.5] transition-colors">
          <Upload className="h-10 w-10 text-[rgb(var(--text-muted))]" />
          <div className="text-center">
            <p className="text-sm font-medium">Click to select a file</p>
            <p className="text-xs text-[rgb(var(--text-muted))]">Supports .xlsx and .csv</p>
          </div>
          <input type="file" accept=".xlsx,.xls,.csv" className="hidden" onChange={handleFileChange} />
        </label>
      )}

      {step === 'map' && preview === null && (
        <div className="flex flex-col gap-4 max-w-lg">
          <p className="text-sm text-[rgb(var(--text-muted))]">
            File: <code className="text-[rgb(var(--text))]">{filePath}</code>
          </p>
          <p className="text-xs text-[rgb(var(--text-muted))]">
            Leave all columns at -1 to auto-detect from the header row, or set them manually.
          </p>
          <div className="grid grid-cols-2 gap-3">
            {(Object.keys(cm) as (keyof ColMapDTO)[]).map(k => (
              <label key={k} className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
                {k} {k === 'alias' || k === 'value' ? <span className="text-red-400">*</span> : ''}
                <input type="number" value={(cm as any)[k]}
                  onChange={e => setCm(prev => ({ ...prev, [k]: parseInt(e.target.value) }))}
                  className="rounded border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-2 py-1.5 text-sm text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]"
                />
              </label>
            ))}
          </div>
          {error && <p className="text-xs text-[rgb(var(--danger))]">{error}</p>}
          <div className="flex gap-2">
            <button onClick={reset} className="flex-1 rounded-lg border border-[rgb(var(--border))] py-2.5 text-sm hover:bg-white/5">
              Back
            </button>
            <button onClick={handlePreview} disabled={loading}
              className="flex-1 rounded-lg bg-[rgb(var(--accent))] py-2.5 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] disabled:opacity-50">
              {loading ? 'Parsing…' : 'Preview'}
            </button>
          </div>
        </div>
      )}

      {step === 'preview' && preview && (
        <div className="flex flex-col gap-4">
          <div className="flex items-center gap-4">
            <div className="flex gap-3">
              <span className="text-xs text-[rgb(var(--text-muted))]">
                <strong className="text-[rgb(var(--text))]">{pending}</strong> to import
              </span>
              {invalid > 0 && (
                <span className="flex items-center gap-1 text-xs text-[rgb(var(--warn))]">
                  <AlertTriangle className="h-3 w-3" />{invalid} invalid (will be skipped)
                </span>
              )}
            </div>
            <div className="ml-auto flex gap-2">
              <button onClick={() => setStep('map')} className="rounded-lg border border-[rgb(var(--border))] px-3 py-2 text-sm hover:bg-white/5">
                Change columns
              </button>
              <button onClick={handleCommit} disabled={loading || pending === 0}
                className="flex items-center gap-2 rounded-lg bg-[rgb(var(--accent))] px-4 py-2 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] disabled:opacity-50">
                <CheckCircle className="h-4 w-4" />
                {loading ? 'Importing…' : `Import ${pending} secrets`}
              </button>
            </div>
          </div>

          {preview.errors.length > 0 && (
            <div className="rounded border border-[rgb(var(--warn)/0.3)] bg-[rgb(var(--warn)/0.05)] p-3 text-xs text-[rgb(var(--warn))]">
              Parse warnings: {preview.errors.join(', ')}
            </div>
          )}

          <div className="overflow-x-auto rounded-lg border border-[rgb(var(--border))]">
            <table className="w-full text-xs">
              <thead className="bg-[rgb(var(--surface))] text-[rgb(var(--text-muted))] uppercase tracking-wider">
                <tr>
                  {['Row','Alias','Provider','Env','Description','Expiry','Status'].map(h => (
                    <th key={h} className="px-3 py-2.5 text-left font-medium border-b border-[rgb(var(--border))]">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {preview.rows.map(r => (
                  <tr key={r.sourceRow} className={`border-b border-[rgb(var(--border)/0.3)] ${r.status === 'invalid' ? 'opacity-40' : ''}`}>
                    <td className="px-3 py-2 text-[rgb(var(--text-muted))]">{r.sourceRow}</td>
                    <td className="px-3 py-2 font-mono font-medium">{r.alias || '—'}</td>
                    <td className="px-3 py-2 text-[rgb(var(--text-muted))]">{r.providerKey}</td>
                    <td className="px-3 py-2">
                      <span className={`rounded px-1.5 py-0.5 ${envBadge(r.environment)}`}>{r.environment}</span>
                    </td>
                    <td className="px-3 py-2 text-[rgb(var(--text-muted))]">{r.description || '—'}</td>
                    <td className="px-3 py-2 text-[rgb(var(--text-muted))]">
                      {r.expiresAt ? new Date(r.expiresAt * 1000).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-3 py-2">
                      {statusBadge(r.status)}
                      {r.statusNote && <span className="ml-1 text-[rgb(var(--text-muted))]">({r.statusNote})</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {error && <p className="text-xs text-[rgb(var(--danger))]">{error}</p>}
        </div>
      )}

      {step === 'done' && result && (
        <div className="flex flex-col items-center gap-6 py-8">
          <CheckCircle className="h-12 w-12 text-[rgb(var(--success))]" />
          <h3 className="text-lg font-semibold">Import Complete</h3>
          <div className="grid grid-cols-3 gap-4 w-full max-w-sm">
            <div className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4 text-center">
              <p className="text-2xl font-bold text-[rgb(var(--success))]">{result.imported}</p>
              <p className="text-xs text-[rgb(var(--text-muted))]">Imported</p>
            </div>
            <div className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4 text-center">
              <p className="text-2xl font-bold text-[rgb(var(--warn))]">{result.invalid}</p>
              <p className="text-xs text-[rgb(var(--text-muted))]">Skipped</p>
            </div>
            <div className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] p-4 text-center">
              <p className="text-2xl font-bold text-[rgb(var(--danger))]">{result.errors.length}</p>
              <p className="text-xs text-[rgb(var(--text-muted))]">Errors</p>
            </div>
          </div>
          {result.errors.length > 0 && (
            <ul className="text-xs text-[rgb(var(--danger))] space-y-0.5 max-w-sm w-full">
              {result.errors.map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          )}
          <div className="rounded-xl border border-yellow-500/30 bg-yellow-500/5 p-4 text-xs text-yellow-300 max-w-sm w-full flex gap-2">
            <Trash2 className="h-4 w-4 mt-0.5 shrink-0" />
            <span>Your secrets are now in Kosh. Please <strong>delete the source file</strong> to remove plaintext credentials from your disk.</span>
          </div>
          <button onClick={reset}
            className="rounded-lg bg-[rgb(var(--accent))] px-6 py-2.5 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))]">
            Import another file
          </button>
        </div>
      )}
    </div>
  )
}
