import { AlertTriangle, Check, CircleDashed, Loader2, MinusCircle } from 'lucide-react'
import { motion, useReducedMotion } from 'motion/react'

import { PIPELINE_STAGES } from '@/features/analyze/pipelineStages'
import type { PipelineStageReport, PipelineStageState, RunState } from '@/types/backend'

interface PipelineTrackProps {
  stages: PipelineStageReport[] | null
  runState: RunState | null
}

const STATE_LABEL: Record<PipelineStageState, string> = {
  pending: 'pending',
  active: 'running',
  done: 'complete',
  failed: 'failed',
  skipped: 'not reached',
}

const RUN_STATE_TONE: Record<RunState, string> = {
  queued: 'tone-info',
  running: 'tone-info',
  succeeded: 'tone-ok',
  failed: 'tone-danger',
  cancelled: 'tone-warn',
}

function StateIcon({ state, spin }: { state: PipelineStageState; spin: boolean }) {
  if (state === 'done') return <Check size={14} aria-hidden="true" />
  if (state === 'failed') return <AlertTriangle size={14} aria-hidden="true" />
  if (state === 'skipped') return <MinusCircle size={14} aria-hidden="true" />
  if (state === 'active') {
    return <Loader2 size={14} className={spin ? 'wx-spin' : undefined} aria-hidden="true" />
  }
  return <CircleDashed size={14} aria-hidden="true" />
}

export function PipelineTrack({ stages, runState }: PipelineTrackProps) {
  const reduceMotion = useReducedMotion()

  const reportFor = (id: string): PipelineStageReport =>
    stages?.find((stage) => stage.id === id) ?? {
      id: id as PipelineStageReport['id'],
      state: 'pending',
      evidence: [],
      started_at: null,
      finished_at: null,
    }

  return (
    <section className="wx-panel" aria-labelledby="wx-pipeline-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="wx-pipeline-title">
          Pipeline
        </span>
        <span className={`wx-pill wx-mono ${runState ? RUN_STATE_TONE[runState] : ''}`}>
          <i aria-hidden="true" /> {runState ?? 'idle'}
        </span>
      </div>

      <div className="wx-track">
        {PIPELINE_STAGES.map((spec) => {
          const report = reportFor(spec.id)
          return (
            <div className={`wx-stage state-${report.state}`} key={spec.id}>
              <div className="wx-stage-node" aria-hidden="true">
                <spec.icon size={15} strokeWidth={1.8} />
              </div>

              <div style={{ minWidth: 0 }}>
                <div className="wx-stage-label">
                  <span className="wx-mono wx-stage-index">{spec.index}</span>
                  <span className="wx-mono" style={{ fontSize: 11, letterSpacing: '0.1em' }}>
                    {spec.label}
                  </span>
                </div>
                <p className="wx-stage-note">{spec.note}</p>
                <p className="wx-stage-module">{spec.module}</p>

                {report.state === 'active' && (
                  <div className="wx-activity" role="progressbar" aria-label={`${spec.label} running`}>
                    <i />
                  </div>
                )}

                {report.evidence.length > 0 && (
                  <motion.div
                    className="wx-stage-evidence"
                    initial={reduceMotion ? false : { opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.24 }}
                  >
                    {report.evidence.map((item) => (
                      <span className="wx-chip" key={`${spec.id}-${item.label}`}>
                        <b>{item.label}</b>
                        {item.value}
                      </span>
                    ))}
                  </motion.div>
                )}
              </div>

              <div className="wx-stage-state wx-mono">
                <StateIcon state={report.state} spin={!reduceMotion} />
                {STATE_LABEL[report.state]}
              </div>
            </div>
          )
        })}
      </div>

      <div className="wx-panel-body is-tight" style={{ borderTop: '1px solid var(--c-line)' }}>
        <p className="wx-stage-note" style={{ margin: 0 }}>
          A stage turns complete only when the run reporter returns its evidence. Nothing on this
          track advances on a timer of its own.
        </p>
      </div>
    </section>
  )
}
