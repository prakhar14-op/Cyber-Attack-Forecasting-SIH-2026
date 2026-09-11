import { Info } from 'lucide-react'

import type { ProgressionStep } from '@/features/dashboard/dashboardSelectors'
import { formatInt, formatSeconds, formatWindowStart } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'

/**
 * Observed progression only. `predict_file` returns no k-step stage prediction,
 * so no step is marked as a forecast direction — the panel says so instead of
 * implying one.
 */
export function AttackProgression({ steps }: { steps: ProgressionStep[] }) {
  return (
    <section className="wx-panel" aria-labelledby="dash-progress-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="dash-progress-title">
          Attack progression
        </span>
        <span className="wx-mono">observed order</span>
      </div>

      <div className="wx-panel-body">
        <div className="dash-progression">
          {steps.map((step, index) => (
            <div
              className={`dash-step${step.isCurrent ? ' is-current' : ''}`}
              key={step.stage}
              style={{ paddingInline: 4 }}
            >
              <span className="dash-step-node" style={{ color: stageColor(step.stage) }}>
                {String(index + 1).padStart(2, '0')}
              </span>
              <div style={{ minWidth: 0 }}>
                <div className="dash-step-title" style={{ fontSize: 13 }}>
                  {stageLabel(step.stage)}
                </div>
                <div className="wx-mono" style={{ marginTop: 4, color: 'var(--c-text-muted)' }}>
                  {formatWindowStart(step.firstWindow)} → {formatWindowStart(step.lastWindow)} ·{' '}
                  {formatInt(step.alerts)} alerts ·{' '}
                  {formatSeconds(step.lastWindow - step.firstWindow)} active
                </div>
              </div>
              {step.isCurrent && (
                <span className="wx-pill wx-mono tone-info">
                  <i aria-hidden="true" /> latest
                </span>
              )}
            </div>
          ))}
        </div>

        <div className="wx-notice" style={{ marginTop: 12 }} role="note">
          <Info size={15} aria-hidden="true" />
          <div>
            These are the stages the capture actually produced, ordered by first alert. The result
            contains no k-step stage prediction, so no next stage is asserted here.
          </div>
        </div>
      </div>
    </section>
  )
}
