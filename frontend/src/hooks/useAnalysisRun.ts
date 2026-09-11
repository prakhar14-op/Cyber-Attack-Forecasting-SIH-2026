import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import { validateCapture } from '@/features/analyze/validateCapture'
import { analysisEngine } from '@/services/analysisEngine'
import type { RunController, RunSnapshot, RunTarget } from '@/services/analysisEngine'
import { useAnalysisSession } from '@/services/analysisSessionContext'
import type { DemoSource } from '@/types/backend'

/** `configs/eval.yaml :: fpr_budgets` — the two budgets the engine persists. */
export const FPR_BUDGETS = [0.001, 0.01] as const
export type FprBudget = (typeof FPR_BUDGETS)[number]

export interface SelectedInput {
  target: RunTarget
  label: string
  detail: string
  bytes: number
  kind: 'pcap' | 'csv'
  /** Set when this selection cannot be executed by the current engine. */
  blockedReason: string | null
}

export interface UseAnalysisRun {
  input: SelectedInput | null
  validationError: string | null
  snapshot: RunSnapshot | null
  isRunning: boolean
  canRun: boolean
  fprBudget: FprBudget
  setFprBudget: (budget: FprBudget) => void
  selectSource: (source: DemoSource) => void
  /** Select a bundled source and start it in one action (the demo path). */
  runSource: (source: DemoSource) => void
  selectFile: (file: File) => void
  clearInput: () => void
  start: () => void
  cancel: () => void
  reset: () => void
}

export function useAnalysisRun(): UseAnalysisRun {
  const { commit } = useAnalysisSession()
  const [input, setInput] = useState<SelectedInput | null>(null)
  const [validationError, setValidationError] = useState<string | null>(null)
  const [snapshot, setSnapshot] = useState<RunSnapshot | null>(null)
  const [fprBudget, setFprBudget] = useState<FprBudget>(0.01)
  const controller = useRef<RunController | null>(null)

  useEffect(
    () => () => {
      controller.current?.cancel()
      controller.current = null
    },
    [],
  )

  const selectSource = useCallback((source: DemoSource) => {
    setValidationError(
      source.available
        ? null
        : `${source.label} is not present in this checkout${source.build_hint ? ` — build it with: ${source.build_hint}` : ''}.`,
    )
    if (!source.available) return
    setSnapshot(null)
    setInput({
      target: { type: 'source', source },
      label: source.path.split('/').pop() ?? source.path,
      detail: source.path,
      bytes: source.bytes ?? 0,
      kind: source.kind,
      blockedReason: null,
    })
  }, [])

  const selectFile = useCallback((file: File) => {
    const check = validateCapture(file)
    if (!check.ok) {
      setValidationError(check.error)
      setInput(null)
      return
    }

    setValidationError(null)
    setSnapshot(null)

    // A dropped copy of a bundled input is recognised and runs as that source.
    if (check.bundled) {
      setInput({
        target: { type: 'source', source: check.bundled },
        label: file.name,
        detail: `recognised as ${check.bundled.path}`,
        bytes: file.size,
        kind: check.bundled.kind,
        blockedReason: null,
      })
      return
    }

    setInput({
      target: { type: 'upload', file, kind: check.kind },
      label: file.name,
      detail: check.kind === 'pcap' ? 'PCAP · full feature path' : 'flow CSV · flow-only path',
      bytes: file.size,
      kind: check.kind,
      blockedReason: analysisEngine.acceptsUploads
        ? null
        : 'This build runs the bundled demo sources only. Analysing an operator-supplied capture needs the local engine service.',
    })
  }, [])

  const clearInput = useCallback(() => {
    setInput(null)
    setValidationError(null)
  }, [])

  const isRunning = snapshot?.run.state === 'queued' || snapshot?.run.state === 'running'

  const beginRun = useCallback(
    (target: RunTarget) => {
      controller.current?.cancel()
      controller.current = analysisEngine.start(target, fprBudget, (next) => {
        setSnapshot(next)
        if (next.run.state === 'succeeded' && next.result) {
          commit({
            runId: next.run.id,
            input: next.run.input,
            fprBudget: next.run.fpr_budget,
            isFixture: analysisEngine.kind === 'demo',
            completedAt: Date.now(),
            result: next.result,
            ledger: next.ledger,
            annotation: next.annotation,
          })
        }
      })
    },
    [commit, fprBudget],
  )

  const start = useCallback(() => {
    if (!input || input.blockedReason || isRunning) return
    beginRun(input.target)
  }, [beginRun, input, isRunning])

  const runSource = useCallback(
    (source: DemoSource) => {
      if (isRunning) return
      selectSource(source)
      if (!source.available) return
      beginRun({ type: 'source', source })
    },
    [beginRun, isRunning, selectSource],
  )

  const cancel = useCallback(() => {
    controller.current?.cancel()
    controller.current = null
  }, [])

  const reset = useCallback(() => {
    controller.current?.cancel()
    controller.current = null
    setSnapshot(null)
  }, [])

  const canRun = useMemo(
    () => Boolean(input) && !input?.blockedReason && !isRunning,
    [input, isRunning],
  )

  return {
    input,
    validationError,
    snapshot,
    isRunning: Boolean(isRunning),
    canRun,
    fprBudget,
    setFprBudget,
    selectSource,
    runSource,
    selectFile,
    clearInput,
    start,
    cancel,
    reset,
  }
}
