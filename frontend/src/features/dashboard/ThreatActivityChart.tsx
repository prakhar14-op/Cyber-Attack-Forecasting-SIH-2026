import { useReducedMotion } from 'motion/react'
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import type { TimelinePoint } from '@/features/dashboard/dashboardSelectors'
import { formatPercent, formatProbability, formatWindowStart } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'
import type { AttackStage } from '@/types/backend'

interface ThreatActivityChartProps {
  points: TimelinePoint[]
  threshold: number
}

interface DotProps {
  cx?: number
  cy?: number
  payload?: TimelinePoint
}

/** Every plotted point is an alert; its colour is its stage. */
function renderStageDot(props: DotProps & { key?: string }) {
  const { cx, cy, payload, key } = props
  if (cx === undefined || cy === undefined || !payload) return <g key={key} />
  return (
    <circle
      key={key}
      cx={cx}
      cy={cy}
      r={3.4}
      fill={stageColor(payload.stage)}
      stroke="var(--c-panel)"
      strokeWidth={1}
    />
  )
}

interface TooltipPayload {
  active?: boolean
  payload?: Array<{ payload: TimelinePoint }>
}

function ThreatTooltip({ active, payload }: TooltipPayload) {
  const point = payload?.[0]?.payload
  if (!active || !point) return null
  return (
    <div
      className="wx-mono"
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
      <div style={{ fontWeight: 700 }}>window {formatWindowStart(point.windowStart)}</div>
      <div>network score {formatProbability(point.networkScore)}</div>
      <div>top host {point.host}</div>
      <div style={{ color: stageColor(point.stage) }}>stage {stageLabel(point.stage)}</div>
      <div>hosts alerting {point.hostsAlerting}</div>
    </div>
  )
}

export function ThreatActivityChart({ points, threshold }: ThreatActivityChartProps) {
  const reduceMotion = useReducedMotion()
  const stagesPresent = [...new Set(points.map((point) => point.stage))] as AttackStage[]

  return (
    <section className="wx-panel" aria-labelledby="dash-threat-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="dash-threat-title">
          Threat activity · network score over window time
        </span>
        <span className="wx-mono">score = max over hosts in window</span>
      </div>

      <div className="wx-panel-body">
        <div style={{ width: '100%', height: 336 }}>
          <ResponsiveContainer>
            <ComposedChart data={points} margin={{ top: 10, right: 18, bottom: 4, left: -12 }}>
              <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
              <XAxis
                dataKey="windowStart"
                tickFormatter={(value: number) => formatWindowStart(value)}
                stroke="var(--chart-axis)"
                tick={{ fill: 'var(--c-text-muted)', fontSize: 10 }}
                tickMargin={8}
                minTickGap={38}
              />
              <YAxis
                domain={[0, 1]}
                ticks={[0, 0.25, 0.5, 0.75, 1]}
                tickFormatter={(value: number) => formatPercent(value, 0)}
                stroke="var(--chart-axis)"
                tick={{ fill: 'var(--c-text-muted)', fontSize: 10 }}
                width={58}
              />
              <Tooltip content={<ThreatTooltip />} />
              <ReferenceLine
                y={threshold}
                stroke="var(--c-danger)"
                strokeDasharray="5 4"
                label={{
                  value: `threshold ${formatProbability(threshold)}`,
                  position: 'insideTopRight',
                  fill: 'var(--c-danger)',
                  fontSize: 10,
                }}
              />
              <Area
                type="monotone"
                dataKey="networkScore"
                stroke="none"
                fill="var(--c-accent)"
                fillOpacity={0.08}
                isAnimationActive={!reduceMotion}
                animationDuration={600}
              />
              <Line
                type="monotone"
                dataKey="networkScore"
                stroke="var(--c-accent)"
                strokeWidth={1.6}
                dot={renderStageDot}
                activeDot={{ r: 5, fill: 'var(--c-accent)' }}
                isAnimationActive={!reduceMotion}
                animationDuration={600}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginTop: 10 }}>
          {stagesPresent.map((stage) => (
            <span className="stage-badge" style={{ color: stageColor(stage) }} key={stage}>
              <i aria-hidden="true" /> {stageLabel(stage)}
            </span>
          ))}
        </div>

        <p className="wx-stage-note" style={{ marginTop: 10 }}>
          The result carries only host-windows at or above the threshold, so this is the alert
          timeline — sub-threshold windows are not part of the engine output and are not drawn.
        </p>
      </div>
    </section>
  )
}
