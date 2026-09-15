import { AlertTriangle, Ban } from 'lucide-react'
import { useReducedMotion } from 'motion/react'
import { useCallback } from 'react'
import { useNavigate } from 'react-router'

import { AnalyzeHeader } from '@/features/analyze/AnalyzeHeader'
import { CaptureIngest } from '@/features/analyze/CaptureIngest'
import { CompletionSummary } from '@/features/analyze/CompletionSummary'
import { DataOriginNotice } from '@/features/analyze/DataOriginNotice'
import { DemoSourceList } from '@/features/analyze/DemoSourceList'
import { PipelineTrack } from '@/features/analyze/PipelineTrack'
import { RunControls } from '@/features/analyze/RunControls'
import { useAnalysisRun } from '@/hooks/useAnalysisRun'
import { useAutoAdvance } from '@/hooks/useAutoAdvance'
import { analysisEngine, ENGINE_IS_DEMO } from '@/services/analysisEngine'
import type { DemoSource } from '@/types/backend'

export default function AnalyzePage() {
  const navigate = useNavigate()
  const reduceMotion = useReducedMotion()
  const run = useAnalysisRun()

  const runState = run.snapshot?.run.state ?? null
  const summary = run.snapshot?.run.summary ?? null
  const error = run.snapshot?.run.error ?? null
  const cancelled = runState === 'cancelled'

  const openDashboard = useCallback(() => {
    navigate('/dashboard')
  }, [navigate])

  const autoAdvance = useAutoAdvance(
    runState === 'succeeded' && Boolean(summary),
    reduceMotion ? 900 : 2400,
    openDashboard,
  )

  const handleStart = useCallback(() => {
    run.start()
    navigate('/dashboard?stream=live')
  }, [run, navigate])

  const handleRunSource = useCallback(
    (source: DemoSource) => {
      run.runSource(source)
      navigate('/dashboard?stream=live')
    },
    [run, navigate],
  )

  return (
    <div>
      <AnalyzeHeader />

      {ENGINE_IS_DEMO && (
        <div style={{ marginTop: 16 }}>
          <DataOriginNotice />
        </div>
      )}

      <div className="wx-columns">
        <div className="wx-stack">
          <CaptureIngest
            input={run.input}
            validationError={run.validationError}
            disabled={run.isRunning}
            scanning={run.isRunning}
            onFile={run.selectFile}
            onClear={run.clearInput}
          />

          <DemoSourceList
            sources={analysisEngine.listSources()}
            selectedPath={
              run.input?.target.type === 'source' ? run.input.target.source.path : null
            }
            disabled={run.isRunning}
            onSelect={run.selectSource}
            onRunSource={handleRunSource}
          />

          <RunControls
            input={run.input}
            runState={runState}
            isRunning={run.isRunning}
            canRun={run.canRun}
            fprBudget={run.fprBudget}
            onBudgetChange={run.setFprBudget}
            onStart={handleStart}
            onCancel={run.cancel}
            onReset={run.reset}
          />
        </div>

        <div className="wx-stack">
          <PipelineTrack stages={run.snapshot?.run.stages ?? null} runState={runState} />

          {cancelled && (
            <div className="wx-notice tone-warn" role="status">
              <Ban size={15} aria-hidden="true" />
              <div>
                Run cancelled. No forecast, explanation or ledger record was produced for this
                input.
              </div>
            </div>
          )}

          {error && (
            <div className="wx-notice tone-danger" role="alert">
              <AlertTriangle size={15} aria-hidden="true" />
              <div>
                <strong className="wx-mono" style={{ display: 'block', marginBottom: 4 }}>
                  {error.type}
                </strong>
                {error.message}
                {error.hint && (
                  <div style={{ marginTop: 6 }}>
                    <code>{error.hint}</code>
                  </div>
                )}
              </div>
            </div>
          )}

          {summary && (
            <CompletionSummary
              summary={summary}
              ledger={run.snapshot?.ledger ?? null}
              autoAdvanceIn={autoAdvance.remaining}
              onContinue={openDashboard}
              onStay={autoAdvance.cancel}
            />
          )}
        </div>
      </div>
    </div>
  )
}
