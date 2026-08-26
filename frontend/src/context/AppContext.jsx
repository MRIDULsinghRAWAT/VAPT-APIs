import { createContext, useContext, useState } from 'react'

const AppContext = createContext(null)

export function AppProvider({ children }) {
  const [parsedSpec, setParsedSpec] = useState(null)
  const [scans, setScans] = useState([])

  return (
    <AppContext.Provider value={{ parsedSpec, setParsedSpec, scans, setScans }}>
      {children}
    </AppContext.Provider>
  )
}

export function useAppContext() {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useAppContext must be used within AppProvider')
  return ctx
}
