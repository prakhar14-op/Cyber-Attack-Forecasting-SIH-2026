import { formatPercent, formatSeconds, formatWindowStart } from '@/lib/format'
import type { TopWindow } from '@/types/backend'

interface ContributingWindowsProps {
  windows: TopWindow[]
  alertWindow: number
  threshold: number
}

const W = 560
const H = 96

/**
 * Where the evidence formed: the host's strongest windows inside the causal
 * context leading up to the alert, plotted on their real time offsets.
 */
export function ContributingWindows({ windows, alertWindow, threshold }: ContributingWindowsProps) {
  const ordered = [...windows].sort((a, b) => a.window_start - b.window_start)
  const oldest = ordered[0]?.window_start ?? alertWindow
  const span = Math.max(alertWindow - oldest, 5)
  const x = (time: number) => 40 + ((time - oldest) / span) * (W - 90)
  const y = (probability: number) => 20 + (1 - probability) * (H - 46)

  return (
    <section className="wx-panel" aria-labelledby="incident-windows-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="incident-windows-title">
          Contributing windows
        </span>
        <span className="wx-mono">causal context · newest at the alert</span>
      </div>

      <div className="wx-panel-body">
        {ordered.length === 0 ? (
          <p className="wx-stage-note" style={{ margin: 0 }}>
            This alert cites no contributing window.
          </p>
        ) : (
          <>
            <svg viewBox={`0 0 ${W} ${H}`} style={{ display: 'block', width: '100%', height: 'auto' }} role="img" aria-label={`${ordered.length} contributing windows`}>
              <line
                x1={40}
                x2={W - 50}
                y1={y(threshold)}
                y2={y(threshold)}
                stroke="var(--c-danger)"
                strokeDasharray="4 4"
                strokeOpacity={0.6}
              />
              <polyline
                points={ordered.map((window) => `${x(window.window_start)},${y(window.probability)}`).join(' ')}
                fill="none"
                stroke="var(--c-accent)"
                strokeWidth={1.4}
              />
              {ordered.map((window) => (
                <g key={window.window_start}>
                  <circle
                    cx={x(window.window_start)}
                    cy={y(window.probability)}
                    r={window.seconds_before_alert === 0 ? 6 : 4}
                    fill={window.seconds_before_alert === 0 ? 'var(--c-danger)' : 'var(--c-accent)'}
                  />
                  <text
                    x={x(window.window_start)}
                    y={y(window.probability) - 10}
                    textAnchor="middle"
                    fontFamily="SFMono-Regular, Consolas, monospace"
                    fontSize={9}
                    fill="var(--c-text-muted)"
                  >
                    {formatPercent(window.probability, 0)}
                  </text>
                  <text
                    x={x(window.window_start)}
                    y={H - 6}
                    textAnchor="middle"
                    fontFamily="SFMono-Regular, Consolas, monospace"
                    fontSize={8.5}
                    fill="var(--c-text-muted)"
                  >
                    −{window.seconds_before_alert}s
                  </text>
                </g>
              ))}
            </svg>

            <table className="dash-table" style={{ marginTop: 10 }}>
              <thead>
                <tr>
                  <th scope="col">Window start</th>
                  <th scope="col">Probability</th>
                  <th scope="col">Before alert</th>
                </tr>
              </thead>
              <tbody>
                {[...windows].map((window) => (
                  <tr key={window.window_start} style={{ cursor: 'default' }}>
                    <td>{formatWindowStart(window.window_start)}</td>
                    <td>{formatPercent(window.probability, 2)}</td>
                    <td>
                      {window.seconds_before_alert === 0
                        ? 'the alert window'
                        : formatSeconds(window.seconds_before_alert)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </section>
  )
}
