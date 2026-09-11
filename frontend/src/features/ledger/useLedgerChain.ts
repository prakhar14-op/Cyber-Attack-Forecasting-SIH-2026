import { useCallback, useEffect, useMemo, useState } from 'react'

import {
  buildChain,
  chainHead,
  checkpoint,
  cryptoAvailable,
  rewriteChain,
  tamperRecord,
  verify,
  verifyAgainstCheckpoint,
  type AnchorResult,
  type ChainEntry,
  type Checkpoint,
  type ForecastRecordInput,
  type VerifyResult,
} from '@/lib/ledgerChain'
import type { Forecast } from '@/types/backend'

/** Which of the two documented tamper modes (if any) is currently applied. */
export type TamperMode = 'none' | 'edit' | 'rewrite'

export interface LedgerChainState {
  phase: 'idle' | 'computing' | 'ready' | 'error'
  error: string | null
  /** The current (possibly tampered) chain. */
  entries: ChainEntry[]
  /** The head of the clean chain, anchored before any tampering. */
  clean: ChainEntry[]
  /** The checkpoint anchored over the clean chain. */
  anchoredCheckpoint: Checkpoint | null
  /** Real result of recomputing the hash chain. */
  verifyResult: VerifyResult | null
  /** Real result of the anchored (head + Merkle) check. */
  anchorResult: AnchorResult | null
  currentHead: string
  tamperMode: TamperMode
  /** Index the tamper acted on (defaults to 0). */
  tamperedIndex: number | null
}

const INITIAL: LedgerChainState = {
  phase: 'idle',
  error: null,
  entries: [],
  clean: [],
  anchoredCheckpoint: null,
  verifyResult: null,
  anchorResult: null,
  currentHead: '',
  tamperMode: 'none',
  tamperedIndex: null,
}

function toRecords(forecasts: Forecast[]): ForecastRecordInput[] {
  // Exactly the fields engine/predict.py appends, in result.forecasts order.
  return forecasts.map((f) => ({
    host: f.host,
    window_start: f.window_start,
    probability: f.probability,
    stage: f.stage,
    technique: f.technique,
  }))
}

/**
 * Owns all Web Crypto work for the ledger page: building the clean chain,
 * anchoring a checkpoint, and applying / reverting the two real tamper modes.
 * Every verification and anchor result it exposes was computed, never assumed.
 */
export function useLedgerChain(forecasts: Forecast[]): {
  state: LedgerChainState
  tamperEdit: (index: number) => Promise<void>
  tamperRewrite: (index: number) => Promise<void>
  restore: () => Promise<void>
} {
  const [state, setState] = useState<LedgerChainState>(INITIAL)

  const records = useMemo(() => toRecords(forecasts), [forecasts])

  // Recompute both real checks for a candidate chain and its anchored checkpoint.
  const evaluate = useCallback(
    async (
      entries: ChainEntry[],
      clean: ChainEntry[],
      cp: Checkpoint,
      mode: TamperMode,
      tamperedIndex: number | null,
    ): Promise<LedgerChainState> => {
      const verifyResult = await verify(entries)
      const anchorResult = await verifyAgainstCheckpoint(entries, cp)
      return {
        phase: 'ready',
        error: null,
        entries,
        clean,
        anchoredCheckpoint: cp,
        verifyResult,
        anchorResult,
        currentHead: chainHead(entries),
        tamperMode: mode,
        tamperedIndex,
      }
    },
    [],
  )

  useEffect(() => {
    let cancelled = false

    if (!cryptoAvailable()) {
      setState({
        ...INITIAL,
        phase: 'error',
        error:
          'Web Crypto (crypto.subtle) is unavailable in this context. Real hashing needs a ' +
          'secure context (https:// or localhost).',
      })
      return
    }

    setState((prev) => ({ ...prev, phase: 'computing', error: null }))

    void (async () => {
      try {
        const clean = await buildChain(records)
        const cp = await checkpoint(clean)
        const next = await evaluate(clean, clean, cp, 'none', null)
        if (!cancelled) setState(next)
      } catch (err) {
        if (!cancelled) {
          setState({
            ...INITIAL,
            phase: 'error',
            error: err instanceof Error ? err.message : String(err),
          })
        }
      }
    })()

    return () => {
      cancelled = true
    }
  }, [records, evaluate])

  const tamperEdit = useCallback(
    async (index: number) => {
      setState((prev) => {
        if (!prev.anchoredCheckpoint) return prev
        const tampered = tamperRecord(prev.clean, index)
        void evaluate(tampered, prev.clean, prev.anchoredCheckpoint, 'edit', index).then(setState)
        return { ...prev, phase: 'computing' }
      })
    },
    [evaluate],
  )

  const tamperRewrite = useCallback(
    async (index: number) => {
      const cp = state.anchoredCheckpoint
      const clean = state.clean
      if (!cp) return
      setState((prev) => ({ ...prev, phase: 'computing' }))
      const rewritten = await rewriteChain(clean, index)
      const next = await evaluate(rewritten, clean, cp, 'rewrite', index)
      setState(next)
    },
    [state.anchoredCheckpoint, state.clean, evaluate],
  )

  const restore = useCallback(async () => {
    const cp = state.anchoredCheckpoint
    const clean = state.clean
    if (!cp) return
    setState((prev) => ({ ...prev, phase: 'computing' }))
    const next = await evaluate(clean, clean, cp, 'none', null)
    setState(next)
  }, [state.anchoredCheckpoint, state.clean, evaluate])

  return { state, tamperEdit, tamperRewrite, restore }
}
