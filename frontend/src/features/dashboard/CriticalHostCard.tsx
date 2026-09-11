import { ArrowRight, Crosshair } from 'lucide-react'
import { Link } from 'react-router'

import type { HostRow } from '@/features/dashboard/dashboardSelectors'
import { formatPercent, formatSeconds, formatWindowStart } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'

export function CriticalHostCard({ row }: { row: HostRow }) {
  const forecast = row.peakForecast
  const maxContribution = forecast.top_features.reduce(
    (max, feature) => Math.max(max, Math.abs(feature.contribution)),
    0,
  )

  return (
    <section className="wx-panel" aria-labelledby="dash-critical-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="dash-critical-title">
          Investigate first
        </span>
        <span className="wx-pill wx-mono tone-danger">
          <Crosshair size={12} aria-hidden="true" /> highest risk
        </span>
      </div>

      <div className="wx-panel-body" style={{ display: 'grid', gap: 14 }}>
        <div>
          <div className="dash-host" style={{ fontSize: 15 }}>
            {row.host}
          </div>
          <div className="dash-critical-value" style={{ color: stageColor(row.dominantStage) }}>
            {formatPercent(row.peakProbability, 1)}
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
          </div>
        </div>

        <dl style={{ margin: 0 }}>
          <div className="wx-kv wx-mono">
            <dt>Peak window</dt>
            <dd>{formatWindowStart(forecast.window_start)}</dd>
          </div>
          <div className="wx-kv wx-mono">
            <dt>Alerts on host</dt>
            <dd>{row.alerts}</dd>
          </div>
          <div className="wx-kv wx-mono">
            <dt>Precursor span</dt>
            <dd>
              {row.precursorSpanSeconds === null ? '—' : formatSeconds(row.precursorSpanSeconds)}
            </dd>
          </div>
          <div className="wx-kv wx-mono">
            <dt>Flagged flows</dt>
            <dd>{forecast.flagged_flows.length}</dd>
          </div>
        </dl>

        <div>
          <div className="wx-mono" style={{ marginBottom: 8, color: 'var(--c-text-muted)' }}>
            Named-feature evidence
          </div>
          <ul className="dash-evidence">
            {forecast.top_features.map((feature) => (
              <li key={feature.feature}>
                <span>
                  {feature.feature}
                  <span style={{ color: 'var(--c-text-muted)' }}> = {feature.value}</span>
                </span>
                <span className="dash-contrib">
                  <i
                    style={{
                      width: `${
                        maxContribution === 0
                          ? 0
                          : (Math.abs(feature.contribution) / maxContribution) * 46
                      }px`,
                      background: feature.contribution >= 0 ? 'var(--c-danger)' : 'var(--c-accent)',
                    }}
                    aria-hidden="true"
                  />
                  {feature.contribution > 0 ? '+' : ''}
                  {feature.contribution}
                </span>
              </li>
            ))}
          </ul>
        </div>

        <Link className="wx-btn is-primary" to={`/incident/${encodeURIComponent(row.host)}`}>
          Investigate host <ArrowRight size={15} aria-hidden="true" />
        </Link>
      </div>
    </section>
  )
}
