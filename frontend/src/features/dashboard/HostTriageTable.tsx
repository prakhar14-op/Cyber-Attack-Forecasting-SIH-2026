import { ChevronRight } from 'lucide-react'
import { useNavigate } from 'react-router'

import type { HostRow } from '@/features/dashboard/dashboardSelectors'
import { formatInt, formatPercent, formatSeconds } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'

interface HostTriageTableProps {
  rows: HostRow[]
  limit?: number
}

export function HostTriageTable({ rows, limit = 8 }: HostTriageTableProps) {
  const navigate = useNavigate()
  const shown = rows.slice(0, limit)

  const open = (host: string) => navigate(`/incident/${encodeURIComponent(host)}`)

  return (
    <section className="wx-panel" aria-labelledby="dash-triage-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="dash-triage-title">
          Hosts to triage
        </span>
        <span className="wx-mono">
          ranked by peak probability · {shown.length} of {rows.length}
        </span>
      </div>

      <div className="wx-panel-body is-tight" style={{ paddingInline: 4 }}>
        <table className="dash-table">
          <thead>
            <tr>
              <th scope="col">#</th>
              <th scope="col">Source host</th>
              <th scope="col">Peak</th>
              <th scope="col">Alerts</th>
              <th scope="col">Dominant stage</th>
              <th scope="col">Precursor</th>
              <th scope="col" aria-label="Open incident" />
            </tr>
          </thead>
          <tbody>
            {shown.map((row, index) => (
              <tr
                key={row.host}
                tabIndex={0}
                role="link"
                aria-label={`Open incident workspace for ${row.host}`}
                onClick={() => open(row.host)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault()
                    open(row.host)
                  }
                }}
              >
                <td className="dash-rank">{String(index + 1).padStart(2, '0')}</td>
                <td className="dash-host">
                  {row.host}
                  {row.internal === 0 && (
                    <span className="wx-mono" style={{ marginLeft: 7, color: 'var(--c-text-muted)' }}>
                      external
                    </span>
                  )}
                </td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                    <span>{formatPercent(row.peakProbability, 1)}</span>
                    <span className="dash-meter" aria-hidden="true">
                      <i
                        style={{
                          width: `${Math.min(row.peakProbability, 1) * 100}%`,
                          background: stageColor(row.dominantStage),
                        }}
                      />
                    </span>
                  </div>
                </td>
                <td>{formatInt(row.alerts)}</td>
                <td>
                  <span className="stage-badge" style={{ color: stageColor(row.dominantStage) }}>
                    <i aria-hidden="true" /> {stageLabel(row.dominantStage)}
                  </span>
                </td>
                <td>
                  {row.precursorSpanSeconds === null ? '—' : formatSeconds(row.precursorSpanSeconds)}
                </td>
                <td style={{ color: 'var(--c-text-muted)' }}>
                  <ChevronRight size={15} aria-hidden="true" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="wx-panel-body is-tight" style={{ borderTop: '1px solid var(--c-line)' }}>
        <p className="wx-stage-note" style={{ margin: 0 }}>
          Scoring is per source host — a row is the host that originated the traffic, which is what
          the model ranks. Select a row to open its incident workspace.
        </p>
      </div>
    </section>
  )
}
