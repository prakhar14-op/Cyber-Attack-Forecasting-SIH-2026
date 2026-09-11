import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import { AnalysisSessionContext } from '@/services/analysisSessionContext'
import type { AnalysisSessionValue, CompletedAnalysis } from '@/services/analysisSessionContext'

const STORAGE_KEY = 'sih26.analysis.session'

function readStored(): CompletedAnalysis | null {
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as CompletedAnalysis) : null
  } catch {
    return null
  }
}

/**
 * Keeps the last completed analysis for the whole console session. Persisted to
 * sessionStorage (not localStorage) so a finished run survives a route change or
 * reload but never outlives the browser session.
 */
export function AnalysisSessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<CompletedAnalysis | null>(readStored)

  const commit = useCallback((next: CompletedAnalysis) => {
    setSession(next)
    try {
      window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(next))
    } catch {
      /* storage full or blocked: the in-memory session still works */
    }
  }, [])

  const clear = useCallback(() => {
    setSession(null)
    try {
      window.sessionStorage.removeItem(STORAGE_KEY)
    } catch {
      /* nothing to do */
    }
  }, [])

  const value = useMemo<AnalysisSessionValue>(
    () => ({ session, commit, clear }),
    [session, commit, clear],
  )

  return <AnalysisSessionContext.Provider value={value}>{children}</AnalysisSessionContext.Provider>
}
