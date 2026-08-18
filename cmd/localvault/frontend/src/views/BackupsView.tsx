import { useState } from 'react'
import { api } from '../api'
import { HardDrive, Upload, Download } from 'lucide-react'

export default function BackupsView() {
  const [pw, setPw] = useState('')
  const [msg, setMsg] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleExport() {
    if (!pw) { setMsg('Enter your master password first'); return }
    setLoading(true); setMsg('')
    try {
      const bytes = await api.exportBackup(pw)
      const blob = new Blob([new Uint8Array(bytes)], { type: 'application/octet-stream' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `localvault-backup-${new Date().toISOString().slice(0,10)}.lvbak`
      a.click()
      setMsg('Backup saved')
    } catch (e: any) { setMsg('Export failed: ' + e) }
    finally { setLoading(false) }
  }

  async function handleImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file || !pw) { setMsg('Select a file and enter your password'); return }
    setLoading(true); setMsg('')
    try {
      const buf = await file.arrayBuffer()
      const data = Array.from(new Uint8Array(buf))
      const res = await api.importBackup(data, pw)
      setMsg(res.err ? 'Import failed: ' + res.err : 'Import successful')
    } catch (e: any) { setMsg('Import failed: ' + e) }
    finally { setLoading(false) }
  }

  return (
    <div className="flex h-full flex-col items-center justify-center gap-6 p-8">
      <HardDrive className="h-12 w-12 text-[rgb(var(--accent))]" />
      <h2 className="text-lg font-semibold">Encrypted Backups</h2>
      <p className="max-w-sm text-center text-sm text-[rgb(var(--text-muted))]">
        Backups are encrypted with XChaCha20-Poly1305 under a key derived from your master
        password. Only you can restore them.
      </p>

      <div className="w-full max-w-sm">
        <label className="flex flex-col gap-1 text-xs text-[rgb(var(--text-muted))]">
          Master Password (to authenticate the backup)
          <input
            type="password"
            value={pw}
            onChange={e => setPw(e.target.value)}
            placeholder="Enter master password"
            className="rounded-lg border border-[rgb(var(--border))] bg-[rgb(var(--surface))] px-3 py-2.5 text-sm text-[rgb(var(--text))] outline-none focus:border-[rgb(var(--accent))]"
          />
        </label>
      </div>

      <div className="flex gap-3">
        <button
          onClick={handleExport}
          disabled={loading}
          className="flex items-center gap-2 rounded-lg bg-[rgb(var(--accent))] px-4 py-2.5 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))] disabled:opacity-50"
        >
          <Download className="h-4 w-4" /> Export Backup
        </button>
        <label className="flex cursor-pointer items-center gap-2 rounded-lg border border-[rgb(var(--border))] px-4 py-2.5 text-sm hover:bg-white/5">
          <Upload className="h-4 w-4" /> Import Backup
          <input type="file" accept=".lvbak" className="hidden" onChange={handleImport} />
        </label>
      </div>

      {msg && <p className={`text-xs ${msg.includes('failed') ? 'text-[rgb(var(--danger))]' : 'text-[rgb(var(--success))]'}`}>{msg}</p>}
    </div>
  )
}
