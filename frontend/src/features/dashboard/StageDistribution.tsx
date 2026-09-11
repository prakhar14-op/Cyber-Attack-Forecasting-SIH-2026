import { useReducedMotion } from 'motion/react'
import { Bar, BarChart, Cell, ResponsiveContainer, XAxis, YAxis } from 'recharts'

import type { StageCount } from '@/features/dashboard/dashboardSelectors'
import { formatInt, formatPercent } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'

export function StageDistribution({ stages }: { stages: StageCount[] }) {
  const reduceMotion = useReducedMotion()
  const height = Math.max(stages.length * 44, 132)

  return (
    <section className="wx-panel" aria-labelledby="dash-stages-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="dash-stages-title">
          Attack stage distribution
        </span>
        <span className="wx-mono">{stages.length} stages observed</span>
      </div>

      <div className="wx-panel-body">
        <div style={{ width: '100%', height }}>
          <ResponsiveContainer>
            <BarChart
              data={stages}
              layout="vertical"
              margin={{ top: 0, right: 44, bottom: 0, left: 0 }}
              barCategoryGap={12}
            >
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="stage"
                width={132}
                tickFormatter={(value: string) => stageLabel(value as StageCount['stage'])}
                stroke="transparent"
                tick={{ fill: 'var(--c-text-sub)', fontSize: 11 }}
              />
              <Bar
                dataKey="alerts"
                radius={[0, 4, 4, 0]}
                isAnimationActive={!reduceMotion}
                label={{
                  position: 'right',
                  fill: 'var(--c-text-sub)',
                  fontSize: 10,
                  formatter: (value: number) => formatInt(value),
                }}
              >
                {stages.map((entry) => (
                  <Cell key={entry.stage} fill={stageColor(entry.stage)} fillOpacity={0.82} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <dl style={{ margin: '6px 0 0' }}>
          {stages.map((entry) => (
            <div className="wx-kv wx-mono" key={entry.stage}>
              <dt style={{ color: stageColor(entry.stage) }}>{stageLabel(entry.stage)}</dt>
              <dd>
                {formatInt(entry.alerts)} alerts · {formatPercent(entry.share, 0)}
              </dd>
            </div>
          ))}
        </dl>

        <p className="wx-stage-note" style={{ marginTop: 8 }}>
          Stage per window is inferred by the engine's interpretable rules; the deployed model is
          binary attack/benign.
        </p>
      </div>
    </section>
  )
}
