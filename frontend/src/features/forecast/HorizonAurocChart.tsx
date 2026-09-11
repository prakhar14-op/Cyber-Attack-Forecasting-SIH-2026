import { useReducedMotion } from 'motion/react'
import {
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { FORECAST_SOURCE, HORIZON_ROWS } from '@/data/projectResults'

interface HorizonPoint {
  secondsAhead: number
  auroc: number
  approx: boolean
  k: number
}

/**
 * Only the two PUBLISHED horizons are plotted as points. Unpublished horizons
 * are drawn as unlabelled ticks on the axis with no marker — never connected
 * by an invented line. Source: results/forecast.json (not committed).
 */
const PUBLISHED: HorizonPoint[] = HORIZON_ROWS.filter(
  (row): row is (typeof HORIZON_ROWS)[number] & { auroc: number } => row.auroc !== null,
).map((row) => ({
  secondsAhead: row.secondsAhead,
  auroc: row.auroc,
  approx: row.aurocApprox,
  k: row.k,
}))

const ALL_SECONDS = HORIZON_ROWS.map((row) => row.secondsAhead)

interface TooltipPayload {
  active?: boolean
  payload?: Array<{ payload: HorizonPoint }>
}

function HorizonTooltip({ active, payload }: TooltipPayload) {
  const point = payload?.[0]?.payload
  if (!active || !point) return null
  return (
    <div
      className="wx-mono wx-num"
      style={{
        border: '1px solid var(--c-line)',
        borderRadius: 9,
        padding: '9px 11px',
        background: 'var(--c-panel)',
        boxShadow: 'var(--shadow-md)',
        color: 'var(--c-text)',
        fontSize: 10.5,
        lineHeight: 1.7,
        textTransform: 'none',
        letterSpacing: 0,
      }}
    >
      <div style={{ fontWeight: 700 }}>
        k = {point.k} · {point.secondsAhead} s ahead
      </div>
      <div>
        test AUROC {point.approx ? '≈ ' : ''}
        {point.auroc.toFixed(3)}
      </div>
    </div>
  )
}

export function HorizonAurocChart() {
  const reduceMotion = useReducedMotion()

  return (
    <section className="wx-panel" aria-labelledby="fc-auroc-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="fc-auroc-title">
          Test AUROC vs forecast horizon
        </span>
        <span className="wx-mono">2 of 8 horizons published</span>
      </div>

      <div className="wx-panel-body">
        <div style={{ width: '100%', height: 300 }}>
          <ResponsiveContainer>
            <ScatterChart margin={{ top: 12, right: 22, bottom: 18, left: -6 }}>
              <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
              <XAxis
                type="number"
                dataKey="secondsAhead"
                name="seconds ahead"
                domain={[0, 45]}
                ticks={ALL_SECONDS}
                tickFormatter={(value: number) => `${value}s`}
                stroke="var(--chart-axis)"
                tick={{ fill: 'var(--c-text-muted)', fontSize: 10 }}
                tickMargin={8}
                label={{
                  value: 'horizon (seconds ahead)',
                  position: 'insideBottom',
                  offset: -8,
                  fill: 'var(--c-text-muted)',
                  fontSize: 10,
                }}
              />
              <YAxis
                type="number"
                dataKey="auroc"
                domain={[0.5, 1]}
                ticks={[0.5, 0.6, 0.7, 0.8, 0.9, 1]}
                tickFormatter={(value: number) => value.toFixed(2)}
                stroke="var(--chart-axis)"
                tick={{ fill: 'var(--c-text-muted)', fontSize: 10 }}
                width={54}
                label={{
                  value: 'test AUROC',
                  angle: -90,
                  position: 'insideLeft',
                  offset: 16,
                  fill: 'var(--c-text-muted)',
                  fontSize: 10,
                }}
              />
              <Tooltip content={<HorizonTooltip />} cursor={{ strokeDasharray: '4 4' }} />
              <Scatter
                data={PUBLISHED}
                isAnimationActive={!reduceMotion}
                shape="circle"
                line={false}
              >
                {PUBLISHED.map((point) => (
                  <Cell key={point.k} fill="#2563eb" />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        </div>

        <p className="wx-stage-note" style={{ marginTop: 6 }}>
          Only the two published points (k=4 ≈ 0.84 at 20 s, k=8 = 0.890 at 40 s) are drawn. The
          remaining horizon ticks carry no marker — the values are not published in this checkout,
          so no line is interpolated between them.
        </p>
        <p className="wx-stage-note" style={{ marginTop: 4 }}>
          Source: {FORECAST_SOURCE}
        </p>
      </div>
    </section>
  )
}
