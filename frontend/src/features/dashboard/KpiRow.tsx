import { AnimatedNumber } from '@/components/ui/AnimatedNumber'
import type { LeadEvidence } from '@/features/dashboard/dashboardSelectors'
import { formatInt, formatPercent, formatProbability, formatSeconds } from '@/lib/format'
import type { PredictionResult } from '@/types/backend'

interface KpiRowProps {
  result: PredictionResult
  peak: number | null
  lead: LeadEvidence
  isStreaming?: boolean
  streamIndex?: number
  totalWindows?: number
  visibleAlerts?: number
  visiblePeak?: number | null
}

const LEAD_TITLE: Record<LeadEvidence['basis'], string> = {
  engine: 'Lead time',
  precursor: 'Precursor span',
  unavailable: 'Lead time',
}

const LEAD_CAPTION: Record<LeadEvidence['basis'], string> = {
  engine: 'median estimated_lead_seconds',
  precursor: 'widest seconds_before_alert',
  unavailable: 'not present in this result',
}

export function KpiRow({
  result,
  peak,
  lead,
  isStreaming = false,
  streamIndex,
  totalWindows,
  visibleAlerts,
  visiblePeak,
}: KpiRowProps) {
  const displayAlerts = isStreaming && visibleAlerts !== undefined ? visibleAlerts : result.n_alerts
  const displayWindows = isStreaming && streamIndex !== undefined ? streamIndex : result.n_host_windows
  const displayPeak = isStreaming && visiblePeak !== undefined ? visiblePeak : peak

  return (
    <div className="dash-kpis">
      <div className="dash-kpi is-alerts">
        <span className="dash-kpi-rule rule-rose" aria-hidden="true" />
        <div className="wx-mono" style={{ color: 'var(--c-text-muted)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>Active alerts</span>
          {isStreaming && (
            <span className="wx-pill wx-mono tone-warn" style={{ fontSize: 9, minHeight: 18, padding: '1px 6px' }}>
              Scanning
            </span>
          )}
        </div>
        <div className="dash-kpi-value" style={{ color: 'var(--c-danger)' }}>
          <AnimatedNumber value={displayAlerts} format={formatInt} />
        </div>
        <small>
          {isStreaming
            ? 'alerts detected in current telemetry window'
            : 'host-windows at or above threshold'}
        </small>
      </div>

      <div className="dash-kpi is-windows">
        <span className="dash-kpi-rule rule-sky" aria-hidden="true" />
        <div className="wx-mono" style={{ color: 'var(--c-text-muted)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>Host windows</span>
          {isStreaming && totalWindows && (
            <span className="wx-mono" style={{ fontSize: 9, color: 'var(--c-accent)' }}>
              {Math.round(((streamIndex ?? 1) / totalWindows) * 100)}%
            </span>
          )}
        </div>
        <div className="dash-kpi-value">
          <AnimatedNumber value={displayWindows} format={formatInt} />
        </div>
        <small>
          {isStreaming && totalWindows
            ? `streaming window ${streamIndex ?? 1} of ${totalWindows} (15s sliding)`
            : `${formatInt(result.n_flows)} flows · 15 s window / 5 s stride`}
        </small>
      </div>

      <div className="dash-kpi is-peak">
        <span className="dash-kpi-rule rule-purple" aria-hidden="true" />
        <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          Peak threat probability
        </div>
        <div className="dash-kpi-value">
          {displayPeak === null ? '—' : <AnimatedNumber value={displayPeak} format={(v) => formatPercent(v, 1)} />}
        </div>
        <small>
          {isStreaming ? 'highest forecast score in active stream' : 'highest single (host, window) forecast'}
        </small>
      </div>

      <div className={`dash-kpi is-lead${lead.basis === 'precursor' ? ' is-precursor' : ''}`}>
        <span className="dash-kpi-rule rule-mint" aria-hidden="true" />
        <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          {LEAD_TITLE[lead.basis]}
        </div>
        <div
          className="dash-kpi-value"
          style={{
            color: lead.seconds !== null ? 'var(--c-success)' : undefined,
            fontSize: isStreaming ? '1.35rem' : undefined,
          }}
        >
          {isStreaming ? (
            <span style={{ color: 'var(--c-accent)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <span className="wx-spin" style={{ display: 'inline-block' }}>⟳</span>
              Forecasting...
            </span>
          ) : lead.seconds === null ? (
            'n/a'
          ) : (
            formatSeconds(lead.seconds)
          )}
        </div>
        <small title={lead.note}>
          {isStreaming ? 'rolling forward k=1..12 steps (+60s lookahead)' : LEAD_CAPTION[lead.basis]}
        </small>
      </div>

      <div className="dash-kpi is-threshold">
        <span className="dash-kpi-rule rule-amber" aria-hidden="true" />
        <div className="wx-mono" style={{ color: 'var(--c-text-muted)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>Alert threshold</span>
          <span className="wx-pill wx-mono" style={{ fontSize: 9, minHeight: 18, padding: '1px 6px', color: 'var(--c-accent)' }}>
            1.0% FPR
          </span>
        </div>
        <div className="dash-kpi-value" title={`Calibrated decision threshold: ${result.threshold}`}>
          {formatProbability(result.threshold)}
        </div>
        <small>calibrated decision boundary from validation split</small>
      </div>
    </div>
  )
}
