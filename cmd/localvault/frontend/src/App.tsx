import { useCallback, useEffect, useRef, useState } from 'react'
import './style.css'
import UnlockScreen from './components/UnlockScreen'
import Sidebar, { View } from './components/Sidebar'
import TitleBar from './components/TitleBar'
import DashboardView from './views/DashboardView'
import SecretsView from './views/SecretsView'
import ProvidersView from './views/ProvidersView'
import AuditView from './views/AuditView'
import BackupsView from './views/BackupsView'
import SettingsView from './views/SettingsView'
import ImportView from './views/ImportView'
import { api } from './api'
import { EventsOn } from '../wailsjs/runtime/runtime'

const DEFAULT_AUTOLOCK_SECS = 300
const TOUCH_THROTTLE_MS = 15000

export default function App() {
  const [unlocked, setUnlocked] = useState(false)
  const [view, setView]         = useState<View>('dashboard')
  const [lockKey, setLockKey]   = useState(0)

  const timerRef     = useRef<ReturnType<typeof setTimeout> | null>(null)
  const autolockSecs = useRef(DEFAULT_AUTOLOCK_SECS)
  const lastTouch    = useRef(0)

  // UI-only transition to the lock screen. Used when the backend reports it locked the
  // vault (idle auto-lock or a backup restore); the DEK is already gone server-side.
  const forceLockUI = useCallback(() => {
    setUnlocked(false)
    setLockKey(k => k + 1)
  }, [])

  const doLock = useCallback(() => {
    api.lock()
    forceLockUI()
  }, [forceLockUI])

  const resetTimer = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current)
    if (autolockSecs.current > 0) {
      timerRef.current = setTimeout(doLock, autolockSecs.current * 1000)
    }
    // Report activity to the backend (throttled) so its authoritative idle timer resets
    // too. The backend enforces the lock even if this webview is suspended.
    const now = Date.now()
    if (now - lastTouch.current > TOUCH_THROTTLE_MS) {
      lastTouch.current = now
      api.touch()
    }
  }, [doLock])

  useEffect(() => {
    if (!unlocked) {
      if (timerRef.current) clearTimeout(timerRef.current)
      return
    }

    api.getSetting('autolock_seconds').then(v => {
      const n = parseInt(v || String(DEFAULT_AUTOLOCK_SECS))
      autolockSecs.current = isNaN(n) ? DEFAULT_AUTOLOCK_SECS : n
      resetTimer()
    })

    const events = ['mousedown', 'keydown', 'mousemove', 'wheel', 'touchstart'] as const
    events.forEach(ev => window.addEventListener(ev, resetTimer, { passive: true }))
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
      events.forEach(ev => window.removeEventListener(ev, resetTimer))
    }
  }, [unlocked, resetTimer])

  // Honor the backend's authoritative lock (idle auto-lock or post-restore lock).
  useEffect(() => {
    const cancel = EventsOn('vault:locked', () => forceLockUI())
    return () => { cancel() }
  }, [forceLockUI])

  function handleUnlocked() {
    setUnlocked(true)
    setView('dashboard')
  }

  function handleLock() {
    if (timerRef.current) clearTimeout(timerRef.current)
    doLock()
  }

  function handleReset() {
    setUnlocked(false)
    setView('dashboard')
    setLockKey(k => k + 1)
  }

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <TitleBar />
      {!unlocked ? (
        <UnlockScreen key={lockKey} onUnlocked={handleUnlocked} />
      ) : (
        <div className="flex flex-1 overflow-hidden">
          <Sidebar current={view} onChange={setView} onLock={handleLock} />
          <main key={lockKey} className="flex-1 overflow-hidden bg-[rgb(var(--bg))]">
            {view === 'dashboard'  && <DashboardView  onNav={v => setView(v as View)} />}
            {view === 'secrets'    && <SecretsView />}
            {view === 'providers'  && <ProvidersView />}
            {view === 'audit'      && <AuditView />}
            {view === 'backups'    && <BackupsView />}
            {view === 'import'     && <ImportView />}
            {view === 'settings'   && <SettingsView onResetDone={handleReset} />}
          </main>
        </div>
      )}
    </div>
  )
}
