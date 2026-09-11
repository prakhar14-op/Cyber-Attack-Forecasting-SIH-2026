import { FlaskConical } from 'lucide-react'

import { DashboardEmptyState } from '@/features/dashboard/DashboardEmptyState'
import { formatPercent, formatWindowStart } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'
import type { CompletedAnalysis } from '@/services/analysisSessionContext'
import type { Forecast } from '@/types/backend'

function peakForecast(forecasts: Forecast[]): Forecast | null {
  if (forecasts.length === 0) return null
  return forecasts.reduce((best, current) =>
    current.probability > best.probability ? current : best,
  )
}

export function PredictionExplanation({ session }: { session: CompletedAnalysis | null }) {
  const result = session?.result ?? null
  const forecast = result ? peakForecast(result.forecasts) : null

  if (!session || !result || !forecast) {
    return (
      <section className="wx-panel" aria-labelledby="explain-live-title">
        <div className="wx-panel-head">
          <span className="wx-mono" id="explain-live-title">
            Prediction explanation
          </span>
          <span className="wx-mono">live session</span>
        </div>
        <div className="wx-panel-body">
          <DashboardEmptyState />
        </div>
      </section>
    )
  }

  const maxContribution = forecast.top_features.reduce(
    (max, feature) => Math.max(max, Math.abs(feature.contribution)),
    0,
  )

  return (
    <section className="wx-panel" aria-labelledby="explain-live-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="explain-live-title">
          Prediction explanation
        </span>
        <span style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>
          {session.isFixture && (
            <span className="wx-pill wx-mono tone-warn">
              <FlaskConical size={12} aria-hidden="true" /> demo fixture — not engine output
            </span>
          )}
          <span className="wx-mono">highest-probability forecast</span>
        </span>
      </div>

      <div className="wx-panel-body" style={{ display: 'grid', gap: 14 }}>
        <div>
          <div className="dash-host" style={{ fontSize: 15 }}>
            {forecast.host}
          </div>
          <div
            className="wx-num"
            style={{
              margin: '6px 0 0',
              fontSize: '1.9rem',
              fontWeight: 760,
              letterSpacing: '-0.035em',
              lineHeight: 1,
              color: stageColor(forecast.stage),
            }}
          >
            {formatPercent(forecast.probability, 1)}
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
            <span className="wx-pill wx-mono">
              window {formatWindowStart(forecast.window_start)}
            </span>
          </div>
        </div>

        <div>
          <div className="wx-mono" style={{ marginBottom: 8, color: 'var(--c-text-muted)' }}>
            Named-feature contributions (signed)
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

        <p className="wx-stage-note" style={{ margin: 0 }}>
          These are the real TreeSHAP contributions from the analysed capture (engine/explain.py). A
          positive contribution pushes the window toward an alert; a negative one pulls it toward
          benign.
        </p>
      </div>
    </section>
  )
}
