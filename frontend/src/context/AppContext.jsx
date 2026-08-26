import { createContext, useContext, useState, useEffect } from 'react'
import { listScans } from '../services/api'

const AppContext = createContext(null)
const LOCAL_STORAGE_KEY = 'vapt_scans_history_v1'
const SPEC_STORAGE_KEY = 'vapt_active_spec_v1'

export function AppProvider({ children }) {
  // Load initial scans from local storage
  const [scans, setScans] = useState(() => {
    try {
      const saved = localStorage.getItem(LOCAL_STORAGE_KEY)
      return saved ? JSON.parse(saved) : []
    } catch {
      return []
    }
  })

  // Load active spec from local storage
  const [parsedSpec, setParsedSpecState] = useState(() => {
    try {
      const saved = localStorage.getItem(SPEC_STORAGE_KEY)
      return saved ? JSON.parse(saved) : null
    } catch {
      return null
    }
  })

  const [latestFindings, setLatestFindings] = useState([])

  // Persistent spec setter
  const setParsedSpec = (spec) => {
    setParsedSpecState(spec)
    if (spec) {
      localStorage.setItem(SPEC_STORAGE_KEY, JSON.stringify(spec))
    } else {
      localStorage.removeItem(SPEC_STORAGE_KEY)
    }
  }

  // Save scans to localStorage whenever scans change
  useEffect(() => {
    try {
      localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(scans))
    } catch (e) {
      console.error('Failed saving scans to persistent storage', e)
    }
  }, [scans])

  // Sync with Backend SQLite DB on startup if backend is reachable
  useEffect(() => {
    async function syncBackendDB() {
      try {
        const backendScans = await listScans()
        if (backendScans && backendScans.length > 0) {
          setScans((prev) => {
            const map = new Map(prev.map((s) => [s.id, s]))
            backendScans.forEach((bs) => map.set(bs.id, bs))
            return Array.from(map.values()).sort(
              (a, b) => new Date(b.created_at) - new Date(a.created_at)
            )
          })
        }
      } catch {
        // Backend offline, gracefully use local persistent storage
      }
    }
    syncBackendDB()
  }, [])

  const addScan = (newScan) => {
    setScans((prev) => {
      const updated = [newScan, ...prev.filter((s) => s.id !== newScan.id)]
      return updated
    })
    setLatestFindings(newScan.findings || [])
  }

  const deleteScan = (scanId) => {
    setScans((prev) => prev.filter((s) => s.id !== scanId))
  }

  const clearAllScans = () => {
    setScans([])
    localStorage.removeItem(LOCAL_STORAGE_KEY)
  }

  return (
    <AppContext.Provider
      value={{
        parsedSpec,
        setParsedSpec,
        scans,
        setScans,
        addScan,
        deleteScan,
        clearAllScans,
        latestFindings,
        setLatestFindings,
      }}
    >
      {children}
    </AppContext.Provider>
  )
}

export function useAppContext() {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useAppContext must be used within AppProvider')
  return ctx
}
