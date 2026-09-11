import { useReducedMotion } from 'motion/react'
import { Bar, BarChart, Cell, ResponsiveContainer, XAxis, YAxis } from 'recharts'

import { BENCHMARK_ROWS, BENCHMARK_SOURCE } from '@/data/projectResults'

/** Sorted descending by AUROC for readability; colours flag headline / baseline. */
const DATA = [...BENCHMARK_ROWS]
  .sort((a, b) => b.auroc - a.auroc)
  .map((row) => ({
    model: row.model,
    auroc: row.auroc,
    kind: row.kind,
  }))

function barColor(kind: string): string {
  if (kind === 'headline') return '#059669'
  if (kind === 'baseline') return '#b45309'
  return 'var(--c-accent)'
}

/**
 * 2D AUROC bar chart of the same README rows.
 * Source: README.md → Results (eval/ablation.py · budget 0.01).
 */
export function AurocBarChart() {
  const reduceMotion = useReducedMotion()
  const height = Math.max(DATA.length * 40, 260)

  return (
    <section className="wx-panel" aria-labelledby="bm-auroc-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="bm-auroc-title">
          AUROC by model
        </span>
        <span className="wx-mono">test 02-03 Bot</span>
      </div>

      <div className="wx-panel-body">
        <div style={{ width: '100%', height }}>
          <ResponsiveContainer>
            <BarChart
              data={DATA}
              layout="vertical"
              margin={{ top: 0, right: 48, bottom: 0, left: 0 }}
              barCategoryGap={10}
            >
              <XAxis type="number" domain={[0, 1]} hide />
              <YAxis
                type="category"
                dataKey="model"
                width={168}
                stroke="transparent"
                tick={{ fill: 'var(--c-text-sub)', fontSize: 11 }}
              />
              <Bar
                dataKey="auroc"
                radius={[0, 4, 4, 0]}
                isAnimationActive={!reduceMotion}
                label={{
                  position: 'right',
                  fill: 'var(--c-text-sub)',
                  fontSize: 10,
                  formatter: (value: number) => value.toFixed(3),
                }}
              >
                {DATA.map((entry) => (
                  <Cell key={entry.model} fill={barColor(entry.kind)} fillOpacity={0.85} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginTop: 8 }}>
          <span className="stage-badge" style={{ color: '#059669' }}>
            <i aria-hidden="true" /> shipped headline (fused)
          </span>
          <span className="stage-badge" style={{ color: '#b45309' }}>
            <i aria-hidden="true" /> PS-graded baseline (lr)
          </span>
          <span className="stage-badge" style={{ color: 'var(--c-accent)' }}>
            <i aria-hidden="true" /> other configurations
          </span>
        </div>

        <p className="wx-stage-note" style={{ marginTop: 8 }}>
          Source: {BENCHMARK_SOURCE}
        </p>
      </div>
    </section>
  )
}
