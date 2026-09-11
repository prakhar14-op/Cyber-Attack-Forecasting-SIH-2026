import { Eye } from 'lucide-react'

import { TECHNIQUE_MAP } from '@/data/modelArtifacts'
import { stageColor, stageLabel } from '@/lib/stages'
import type { CompletedAnalysis } from '@/services/analysisSessionContext'

/** Techniques that the current session actually emitted (by forecast.technique). */
function seenTechniques(session: CompletedAnalysis | null): Set<string> {
  const seen = new Set<string>()
  if (!session) return seen
  for (const forecast of session.result.forecasts) {
    if (forecast.technique) seen.add(forecast.technique)
  }
  return seen
}

export function MitreTechniqueMap({ session }: { session: CompletedAnalysis | null }) {
  const seen = seenTechniques(session)

  return (
    <section className="wx-panel" aria-labelledby="explain-mitre-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="explain-mitre-title">
          MITRE technique map
        </span>
        <span className="wx-mono">source: engine/technique_map.yaml</span>
      </div>

      <div className="wx-panel-body is-tight" style={{ paddingInline: 4 }}>
        <table className="dash-table">
          <thead>
            <tr>
              <th scope="col">Stage</th>
              <th scope="col">Rule (first match wins)</th>
              <th scope="col">Technique</th>
              <th scope="col">Name</th>
              <th scope="col" aria-label="Seen in this capture" />
            </tr>
          </thead>
          <tbody>
            {TECHNIQUE_MAP.flatMap((entry) =>
              entry.rules.map((rule, ruleIndex) => {
                const isSeen = rule.technique !== null && seen.has(rule.technique)
                return (
                  <tr key={`${entry.stage}-${ruleIndex}`}>
                    <td>
                      {ruleIndex === 0 ? (
                        <span className="stage-badge" style={{ color: stageColor(entry.stage) }}>
                          <i aria-hidden="true" /> {stageLabel(entry.stage)}
                        </span>
                      ) : (
                        <span
                          className="wx-mono"
                          style={{ color: 'var(--c-text-muted)', paddingLeft: 4 }}
                        >
                          ↳
                        </span>
                      )}
                    </td>
                    <td className="wx-mono" style={{ color: 'var(--c-text-sub)' }}>
                      {rule.condition ?? 'default'}
                    </td>
                    <td className="wx-mono">
                      {rule.technique ?? <span style={{ color: 'var(--c-text-muted)' }}>—</span>}
                    </td>
                    <td>
                      {rule.techniqueName}
                      {rule.note && (
                        <span style={{ color: 'var(--c-text-muted)' }}> · {rule.note}</span>
                      )}
                    </td>
                    <td>
                      {isSeen && (
                        <span className="wx-pill wx-mono tone-info">
                          <Eye size={12} aria-hidden="true" /> seen in this capture
                        </span>
                      )}
                    </td>
                  </tr>
                )
              }),
            )}
          </tbody>
        </table>
      </div>

      <div className="wx-panel-body is-tight" style={{ borderTop: '1px solid var(--c-line)' }}>
        <p className="wx-stage-note" style={{ margin: 0 }}>
          Transcribed from <code>engine/technique_map.yaml</code>. The first matching rule per stage
          wins, and only techniques whose evidence exists in the features are mapped — benign maps
          to no technique.
        </p>
      </div>
    </section>
  )
}
