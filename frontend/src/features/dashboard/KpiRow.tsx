import { AnimatedNumber } from '@/components/ui/AnimatedNumber'
import type { LeadEvidence } from '@/features/dashboard/dashboardSelectors'
import { formatInt, formatPercent, formatProbability, formatSeconds } from '@/lib/format'
import type { PredictionResult } from '@/types/backend'

interface KpiRowProps {
  result: PredictionResult
  peak: number | null
  lead: LeadEvidence
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

export function KpiRow({ result, peak, lead }: KpiRowProps) {
  return (
    <div className="dash-kpis">
      <div className="dash-kpi">
        <span className="dash-kpi-rule" style={{ background: 'var(--c-accent)' }} aria-hidden="true" />
        <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          Active alerts
        </div>
        <div className="dash-kpi-value" style={{ color: 'var(--c-accent)' }}>
          <AnimatedNumber value={result.n_alerts} format={formatInt} />
        </div>
        <small>host-windows at or above threshold</small>
      </div>

      <div className="dash-kpi">
        <span className="dash-kpi-rule" aria-hidden="true" />
        <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          Host windows
        </div>
        <div className="dash-kpi-value">
          <AnimatedNumber value={result.n_host_windows} format={formatInt} />
        </div>
        <small>{formatInt(result.n_flows)} flows · 15 s window / 5 s stride</small>
      </div>

      <div className="dash-kpi">
        <span className="dash-kpi-rule" aria-hidden="true" />
        <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          Peak threat probability
        </div>
        <div className="dash-kpi-value">
          {peak === null ? '—' : <AnimatedNumber value={peak} format={(v) => formatPercent(v, 1)} />}
        </div>
        <small>highest single (host, window) forecast</small>
      </div>

      <div className={`dash-kpi${lead.basis === 'precursor' ? ' is-lead' : ''}`}>
        <span className="dash-kpi-rule" aria-hidden="true" />
        <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          {LEAD_TITLE[lead.basis]}
        </div>
        <div className="dash-kpi-value">
          {lead.seconds === null ? 'n/a' : formatSeconds(lead.seconds)}
        </div>
        <small title={lead.note}>{LEAD_CAPTION[lead.basis]}</small>
      </div>

      <div className="dash-kpi">
        <span className="dash-kpi-rule" aria-hidden="true" />
        <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          Alert threshold
        </div>
        <div className="dash-kpi-value">{formatProbability(result.threshold)}</div>
        <small>from the validation split, not tuned here</small>
      </div>
    </div>
  )
}
