import { useMemo, useState } from 'react'

import { BENCHMARK_ROWS, BENCHMARK_SOURCE, type BenchmarkRow } from '@/data/projectResults'

type SortDir = 'asc' | 'desc'

function kindPill(kind: BenchmarkRow['kind']) {
  if (kind === 'headline') {
    return (
      <span className="wx-pill tone-ok">
        <i aria-hidden="true" /> shipped headline
      </span>
    )
  }
  if (kind === 'baseline') {
    return (
      <span className="wx-pill tone-info">
        <i aria-hidden="true" /> PS-graded baseline
      </span>
    )
  }
  return null
}

/**
 * Model comparison table, transcribed EXACTLY from README.md (test split
 * 02-03 Bot, operating point 1% FPR budget). fused is highlighted as the
 * shipped headline, lr as the PS-graded baseline. Sortable by AUROC.
 * Source: README.md → Results (eval/ablation.py · budget 0.01).
 */
export function ModelComparisonTable() {
  const [dir, setDir] = useState<SortDir>('desc')

  const rows = useMemo(() => {
    const sorted = [...BENCHMARK_ROWS].sort((a, b) =>
      dir === 'desc' ? b.auroc - a.auroc : a.auroc - b.auroc,
    )
    return sorted
  }, [dir])

  return (
    <section className="wx-panel" aria-labelledby="bm-table-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="bm-table-title">
          Model comparison · test 02-03 Bot · 1% FPR budget
        </span>
        <button
          type="button"
          className="wx-btn"
          onClick={() => setDir((prev) => (prev === 'desc' ? 'asc' : 'desc'))}
          aria-label={`Sort by AUROC ${dir === 'desc' ? 'ascending' : 'descending'}`}
        >
          AUROC {dir === 'desc' ? '↓' : '↑'}
        </button>
      </div>

      <div className="wx-panel-body is-tight" style={{ overflowX: 'auto' }}>
        <table className="dash-table">
          <thead>
            <tr>
              <th>model</th>
              <th>F1@0.01</th>
              <th>precision@0.01</th>
              <th>recall@0.01</th>
              <th>AUROC</th>
              <th>ECE</th>
              <th>lead_median_s</th>
              <th>lead_IQR_s</th>
              <th>episodes</th>
              <th>alerts/host/day</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.model}
                className={
                  row.kind === 'headline'
                    ? 'dash-row is-primary'
                    : row.kind === 'baseline'
                      ? 'dash-row is-triage'
                      : undefined
                }
              >
                <td className="dash-host">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                    {row.model}
                    {kindPill(row.kind)}
                  </div>
                </td>
                <td className="wx-num">{row.f1.toFixed(3)}</td>
                <td className="wx-num">{row.precision.toFixed(3)}</td>
                <td className="wx-num">{row.recall.toFixed(3)}</td>
                <td className="wx-num" style={{ fontWeight: 700 }}>
                  {row.auroc.toFixed(3)}
                </td>
                <td className="wx-num">{row.ece.toFixed(3)}</td>
                <td className="wx-num">{row.leadMedianS.toFixed(1)}</td>
                <td className="wx-num">{row.leadIqrS}</td>
                <td className="wx-num">{row.episodes}</td>
                <td className="wx-num">{row.alertsPerHostDay.toFixed(1)}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <p className="wx-stage-note" style={{ marginTop: 10 }}>
          Transcribed verbatim from README.md. <strong>fused</strong> is the shipped headline
          (rank-mean of the TGN encoder and XGBoost, selected on validation); <strong>lr</strong> is
          the PS-graded class-weighted logistic-regression baseline.
        </p>
        <p className="wx-stage-note" style={{ marginTop: 4 }}>
          Source: {BENCHMARK_SOURCE}
        </p>
      </div>
    </section>
  )
}
