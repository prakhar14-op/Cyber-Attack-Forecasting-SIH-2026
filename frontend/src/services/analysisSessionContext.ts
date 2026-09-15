import { createContext, useContext } from 'react'

import type { CaptureAnnotation, LedgerStatus, PredictionResult, RunInput } from '@/types/backend'

/** A finished analysis, held so downstream views (dashboard, graph…) reuse it. */
export interface CompletedAnalysis {
  runId: string
  input: RunInput
  fprBudget: number
  /** True when the result came from the demo fixture rather than the engine. */
  isFixture: boolean
  completedAt: number
  result: PredictionResult
  ledger: LedgerStatus | null
  /** Annotated episodes for this capture, or null when none exist. */
  annotation: CaptureAnnotation | null
}

export interface ActiveRunInfo {
  isRunning: boolean
  inputName: string
  fprBudget: number
  stage?: string
  progress?: number
}

export interface AnalysisSessionValue {
  session: CompletedAnalysis | null
  activeRun: ActiveRunInfo | null
  commit: (next: CompletedAnalysis) => void
  setActiveRun: (run: ActiveRunInfo | null) => void
  clear: () => void
  cancelActiveRun?: () => void
}

export const AnalysisSessionContext = createContext<AnalysisSessionValue | null>(null)

export function useAnalysisSession(): AnalysisSessionValue {
  const value = useContext(AnalysisSessionContext)
  if (!value) {
    throw new Error('useAnalysisSession must be used inside <AnalysisSessionProvider>')
  }
  return value
}
