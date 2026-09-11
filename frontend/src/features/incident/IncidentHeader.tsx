import { ShieldAlert } from 'lucide-react'

import type { HostRow } from '@/features/dashboard/dashboardSelectors'
import { highRiskBoundary } from '@/features/graph/graphModel'
import { formatPercent, formatSeconds, formatWindowStart } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'
import type { Forecast } from '@/types/backend'

interface IncidentHeaderProps {
  host: string
  row: HostRow
  forecast: Forecast
  threshold: number
  internal: number | null
}

/** Severity is derived from the run's own threshold, not a hardcoded scale. */
function severityOf(probability: number, threshold: number): { label: string; color: string } {
  if (probability >= highRiskBoundary(threshold)) return { label: 'high', color: 'var(--c-danger)' }
  if (probability >= threshold) return { label: 'elevated', color: 'var(--c-warn)' }
  return { label: 'below threshold', color: 'var(--c-text-muted)' }
}

export function IncidentHeader({ host, row, forecast, threshold, internal }: IncidentHeaderProps) {
  const severity = severityOf(row.peakProbability, threshold)

  return (
    <section className="wx-panel" aria-labelledby="incident-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="incident-title">
          Incident · source host
        </span>
        <span className="wx-mono">
          scored unit · (source host, 15 s window)
        </span>
      </div>

      <div
        className="wx-panel-body"
        style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', gap: 18, alignItems: 'start' }}
      >
        <div>
          <div className="dash-host" style={{ fontSize: 20 }}>
            {host}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 12 }}>
            <span className="stage-badge" style={{ color: stageColor(forecast.stage) }}>
              <i aria-hidden="true" /> {stageLabel(forecast.stage)}
            </span>
            {forecast.technique && (
              <span className="wx-pill wx-mono">
                {forecast.technique} · {forecast.technique_name}
              </span>
            )}
            <span className="wx-pill wx-mono" style={{ color: severity.color, borderColor: severity.color }}>
              <ShieldAlert size={12} aria-hidden="true" /> {severity.label}
            </span>
            <span className="wx-pill wx-mono">{internal === 0 ? 'external' : internal === 1 ? 'internal' : 'zone not derived'}</span>
            <span className="wx-pill wx-mono">
              {forecast.estimated_lead_seconds === null
                ? 'engine lead: not set for a single capture'
                : `lead ${formatSeconds(forecast.estimated_lead_seconds)}`}
            </span>
            {row.precursorSpanSeconds !== null && (
              <span className="wx-pill wx-mono tone-info">
                precursor span {formatSeconds(row.precursorSpanSeconds)}
              </span>
            )}
          </div>

          <dl style={{ margin: '16px 0 0', maxWidth: 520 }}>
            <div className="wx-kv wx-mono">
              <dt>Peak window</dt>
              <dd>{formatWindowStart(forecast.window_start)}</dd>
            </div>
            <div className="wx-kv wx-mono">
              <dt>Alerts on host</dt>
              <dd>{row.alerts}</dd>
            </div>
            <div className="wx-kv wx-mono">
              <dt>Dominant stage</dt>
              <dd>{stageLabel(row.dominantStage)}</dd>
            </div>
            <div className="wx-kv wx-mono">
              <dt>Alert threshold</dt>
              <dd>{threshold.toFixed(4)}</dd>
            </div>
          </dl>
        </div>

        <div style={{ textAlign: 'right' }}>
          <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
            Peak probability
          </div>
          <div
            className="dash-critical-value"
            style={{ fontSize: '3.4rem', color: severity.color }}
          >
            {formatPercent(row.peakProbability, 1)}
          </div>
          <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
            vs threshold {formatPercent(threshold, 1)}
          </div>
        </div>
      </div>
    </section>
  )
}
