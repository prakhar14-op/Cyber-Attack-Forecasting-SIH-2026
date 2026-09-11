import { Info, Play, RotateCcw, Square } from 'lucide-react'

import type { FprBudget, SelectedInput } from '@/hooks/useAnalysisRun'
import { FPR_BUDGETS } from '@/hooks/useAnalysisRun'
import type { RunState } from '@/types/backend'

interface RunControlsProps {
  input: SelectedInput | null
  runState: RunState | null
  isRunning: boolean
  canRun: boolean
  fprBudget: FprBudget
  onBudgetChange: (budget: FprBudget) => void
  onStart: () => void
  onCancel: () => void
  onReset: () => void
}

const BUDGET_LABEL: Record<number, string> = { 0.001: '0.1 %', 0.01: '1 %' }

export function RunControls({
  input,
  runState,
  isRunning,
  canRun,
  fprBudget,
  onBudgetChange,
  onStart,
  onCancel,
  onReset,
}: RunControlsProps) {
  const finished = runState === 'succeeded' || runState === 'failed' || runState === 'cancelled'

  return (
    <section className="wx-panel" aria-labelledby="wx-run-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="wx-run-title">
          Analysis controls
        </span>
        <span className="wx-mono">unit · (source host, 15 s window)</span>
      </div>

      <div className="wx-panel-body" style={{ display: 'grid', gap: 14 }}>
        <div>
          <div className="wx-mono" style={{ marginBottom: 7, color: 'var(--c-text-muted)' }}>
            False-positive budget
          </div>
          <div role="group" aria-label="False-positive budget" style={{ display: 'flex', gap: 6 }}>
            {FPR_BUDGETS.map((budget) => (
              <button
                key={budget}
                type="button"
                className={`wx-btn wx-mono${budget === fprBudget ? ' is-primary' : ''}`}
                aria-pressed={budget === fprBudget}
                disabled={isRunning}
                onClick={() => onBudgetChange(budget)}
              >
                {BUDGET_LABEL[budget]}
              </button>
            ))}
          </div>
          <p className="wx-stage-note" style={{ marginTop: 8 }}>
            The alert threshold is the value selected on the validation split for this budget — it
            is loaded from the persisted engine artefacts, never chosen in the UI.
          </p>
        </div>

        {input?.blockedReason && (
          <div className="wx-notice" role="note">
            <Info size={15} aria-hidden="true" />
            <div>{input.blockedReason}</div>
          </div>
        )}

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          <button type="button" className="wx-btn is-primary" disabled={!canRun} onClick={onStart}>
            <Play size={15} aria-hidden="true" />
            {isRunning ? 'Analysis running…' : 'Run Analysis'}
          </button>

          {isRunning && (
            <button type="button" className="wx-btn is-danger" onClick={onCancel}>
              <Square size={13} aria-hidden="true" /> Cancel run
            </button>
          )}

          {finished && (
            <button type="button" className="wx-btn" onClick={onReset}>
              <RotateCcw size={14} aria-hidden="true" /> Clear run
            </button>
          )}
        </div>

        {!input && (
          <p className="wx-stage-note" style={{ margin: 0 }}>
            Select a bundled input or drop a capture to enable the run.
          </p>
        )}
      </div>
    </section>
  )
}
