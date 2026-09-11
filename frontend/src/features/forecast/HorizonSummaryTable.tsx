import { FORECAST_SOURCE, HORIZON_ROWS, KSTEP_OPERATING_POINT } from '@/data/projectResults'

const NOTE_TONE: Record<string, string> = {
  'near-nowcast': 'var(--c-text-muted)',
  'honest horizon': 'var(--c-accent)',
  'threshold stops transferring': 'var(--c-warn)',
}

/**
 * Summary table: horizon k, seconds ahead, test AUROC, operating point at the
 * 1% budget, episodes, note. Unpublished AUROC cells render the literal
 * "not published in this checkout" — never an interpolated value.
 * Source: README.md (M7), docs/limitations.md.
 */
export function HorizonSummaryTable() {
  return (
    <section className="wx-panel" aria-labelledby="fc-table-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="fc-table-title">
          Forecast horizon summary
        </span>
        <span className="wx-mono">k-step head · ranking</span>
      </div>

      <div className="wx-panel-body is-tight">
        <table className="dash-table">
          <thead>
            <tr>
              <th>horizon k</th>
              <th>seconds ahead</th>
              <th>test AUROC</th>
              <th>op. point @ 1% FPR</th>
              <th>episodes</th>
              <th>note</th>
            </tr>
          </thead>
          <tbody>
            {HORIZON_ROWS.map((row) => (
              <tr key={row.k}>
                <td className="wx-num">k = {row.k}</td>
                <td className="wx-num">{row.secondsAhead} s</td>
                <td className="wx-num">
                  {row.auroc === null ? (
                    <span style={{ color: 'var(--c-text-muted)', fontStyle: 'italic' }}>
                      not published in this checkout
                    </span>
                  ) : (
                    `${row.aurocApprox ? '≈ ' : ''}${row.auroc.toFixed(3)}`
                  )}
                </td>
                <td className="wx-num" style={{ color: 'var(--c-warn)' }}>
                  {KSTEP_OPERATING_POINT.f1} F1 · does not fire
                </td>
                <td className="wx-num">{KSTEP_OPERATING_POINT.episodes}</td>
                <td style={{ color: NOTE_TONE[row.note] ?? 'var(--c-text)' }}>{row.note}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <p className="wx-stage-note" style={{ marginTop: 10 }}>
          The operating point is the same for every horizon: the k-step head does not fire at the
          fixed 1% FPR budget (F1 {KSTEP_OPERATING_POINT.f1}, {KSTEP_OPERATING_POINT.episodes}). The
          AUROC column is a <em>ranking</em> measure and is independent of that operating point.
        </p>
        <p className="wx-stage-note" style={{ marginTop: 4 }}>
          Source: {FORECAST_SOURCE}
        </p>
      </div>
    </section>
  )
}
