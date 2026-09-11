import { AlertTriangle, Check, Eye, XCircle } from 'lucide-react'

import { STAGE_COVERAGE, STAGE_COVERAGE_CONSEQUENCE, type CoverageLevel } from '@/data/modelArtifacts'
import { stageColor, stageLabel } from '@/lib/stages'
import type { CompletedAnalysis } from '@/services/analysisSessionContext'
import type { AttackStage } from '@/types/backend'

const LEVEL_PILL: Record<CoverageLevel, { className: string; label: string }> = {
  covered: { className: 'tone-ok', label: 'covered' },
  none: { className: 'tone-warn', label: 'no coverage' },
  zero_windows: { className: 'tone-danger', label: 'zero windows' },
}

function LevelIcon({ level }: { level: CoverageLevel }) {
  if (level === 'covered') return <Check size={12} aria-hidden="true" />
  if (level === 'none') return <AlertTriangle size={12} aria-hidden="true" />
  return <XCircle size={12} aria-hidden="true" />
}

function seenStages(session: CompletedAnalysis | null): Set<AttackStage> {
  const seen = new Set<AttackStage>()
  if (!session) return seen
  for (const forecast of session.result.forecasts) {
    seen.add(forecast.stage)
  }
  return seen
}

export function StageCoverage({ session }: { session: CompletedAnalysis | null }) {
  const seen = seenStages(session)

  return (
    <section className="wx-panel" aria-labelledby="explain-coverage-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="explain-coverage-title">
          Stage coverage
        </span>
        <span className="wx-mono">source: docs/limitations.md · docs/stage_mapping.md</span>
      </div>

      <div className="wx-panel-body is-tight" style={{ paddingInline: 4 }}>
        <table className="dash-table">
          <thead>
            <tr>
              <th scope="col">Stage</th>
              <th scope="col">Training coverage</th>
              <th scope="col">Detail</th>
              <th scope="col" aria-label="Seen in this capture" />
            </tr>
          </thead>
          <tbody>
            {STAGE_COVERAGE.map((entry) => {
              const pill = LEVEL_PILL[entry.level]
              return (
                <tr key={entry.stage}>
                  <td>
                    <span className="stage-badge" style={{ color: stageColor(entry.stage) }}>
                      <i aria-hidden="true" /> {stageLabel(entry.stage)}
                    </span>
                  </td>
                  <td>
                    <span className={`wx-pill wx-mono ${pill.className}`}>
                      <LevelIcon level={entry.level} /> {pill.label}
                    </span>
                  </td>
                  <td style={{ color: 'var(--c-text-sub)', fontSize: 12 }}>{entry.detail}</td>
                  <td>
                    {seen.has(entry.stage) && (
                      <span className="wx-pill wx-mono tone-info">
                        <Eye size={12} aria-hidden="true" /> seen in this capture
                      </span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      <div className="wx-panel-body is-tight" style={{ borderTop: '1px solid var(--c-line)' }}>
        <p className="wx-stage-note" style={{ margin: 0 }}>
          {STAGE_COVERAGE_CONSEQUENCE}
        </p>
      </div>
    </section>
  )
}
