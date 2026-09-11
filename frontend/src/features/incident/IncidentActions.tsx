import { Activity, Info, Network, ShieldMinus } from 'lucide-react'
import { useCallback, useState } from 'react'
import { Link } from 'react-router'

import { formatInt, formatPercent } from '@/lib/format'
import { analysisEngine } from '@/services/analysisEngine'
import type { ContainmentOutcome } from '@/services/analysisEngine'
import type { PredictionResult } from '@/types/backend'

interface IncidentActionsProps {
  host: string
  result: PredictionResult
  /** Seeks the shared replay cursor to this host's first alert. */
  onReplayFromFirstAlert: () => void
}

export function IncidentActions({ host, result, onReplayFromFirstAlert }: IncidentActionsProps) {
  const [outcome, setOutcome] = useState<ContainmentOutcome | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const contain = useCallback(async () => {
    setPending(true)
    setError(null)
    try {
      setOutcome(await analysisEngine.containHost(result, host))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'containment failed')
    } finally {
      setPending(false)
    }
  }, [host, result])

  return (
    <section className="wx-panel" aria-labelledby="incident-actions-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="incident-actions-title">
          Analyst actions
        </span>
        <span className="wx-mono">what-if · graph · replay</span>
      </div>

      <div className="wx-panel-body" style={{ display: 'grid', gap: 12 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          <button type="button" className="wx-btn is-primary" onClick={contain} disabled={pending}>
            <ShieldMinus size={15} aria-hidden="true" />
            {pending ? 'Running ablation…' : 'Contain host'}
          </button>
          <Link className="wx-btn" to="/graph">
            <Network size={14} aria-hidden="true" /> Open attack graph
          </Link>
          <Link className="wx-btn" to="/timeline" onClick={onReplayFromFirstAlert}>
            <Activity size={14} aria-hidden="true" /> Open timeline at first alert
          </Link>
        </div>

        {error && (
          <div className="wx-notice tone-danger" role="alert">
            <Info size={15} aria-hidden="true" />
            <div>{error}</div>
          </div>
        )}

        {outcome && (
          <div style={{ border: '1px solid var(--c-line)', borderRadius: 11, padding: 14 }}>
            <div className="wx-mono" style={{ color: 'var(--c-text-muted)', marginBottom: 10 }}>
              Containment · {outcome.basis === 'engine' ? 'engine re-run' : 'own alert rows'}
            </div>

            <div className="wx-metrics" style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}>
              <div className="wx-metric">
                <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
                  Before
                </div>
                <div className="wx-metric-value">{formatInt(outcome.beforeAlerts)}</div>
                <small>network alerts</small>
              </div>
              <div className="wx-metric">
                <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
                  After containment
                </div>
                <div className="wx-metric-value">{formatInt(outcome.afterAlerts)}</div>
                <small>{formatInt(outcome.hostAlerts)} rows removed</small>
              </div>
              <div className="wx-metric">
                <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
                  Delta
                </div>
                <div className="wx-metric-value" style={{ color: 'var(--c-success)' }}>
                  {outcome.deltaAlerts}
                </div>
                <small>
                  peak {outcome.beforePeak === null ? '—' : formatPercent(outcome.beforePeak, 1)} →{' '}
                  {outcome.afterPeak === null ? 'none' : formatPercent(outcome.afterPeak, 1)}
                </small>
              </div>
            </div>

            <p className="wx-stage-note" style={{ marginTop: 10 }}>
              {outcome.note}
            </p>
          </div>
        )}
      </div>
    </section>
  )
}
