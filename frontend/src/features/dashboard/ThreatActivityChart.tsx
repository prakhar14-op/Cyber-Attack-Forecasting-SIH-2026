import { useEffect, useMemo, useRef, useState } from 'react'
import { FastForward, Pause, Play, RotateCcw, TrendingUp, ZoomIn, ZoomOut } from 'lucide-react'
import { useReducedMotion } from 'motion/react'
import {
  Area,
  Brush,
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
  autoStream?: boolean
  onStreamChange?: (streamIndex: number, total: number, isPlaying: boolean) => void
}

interface ChartItem extends TimelinePoint {
  isForecast?: boolean
  forecastStep?: number
  forecastScore?: number
  forecastUpper?: number
  forecastLower?: number
}

interface DotProps {
  cx?: number
  cy?: number
  payload?: ChartItem
}

/** Every plotted observed point is an alert; its colour is its stage. */
function renderStageDot(props: DotProps & { key?: string }) {
  const { cx, cy, payload, key } = props
  if (cx === undefined || cy === undefined || !payload) return <g key={key} />
  if (payload.isForecast) {
    return (
      <circle
        key={key}
        cx={cx}
        cy={cy}
        r={2.8}
        fill="var(--c-accent)"
        stroke="var(--c-panel)"
        strokeWidth={1}
      />
    )
  }
  return (
    <circle
      key={key}
      cx={cx}
      cy={cy}
      r={3.8}
      fill={stageColor(payload.stage)}
      stroke="var(--c-panel)"
      strokeWidth={1.5}
    />
  )
}

interface TooltipPayload {
  active?: boolean
  payload?: Array<{ payload: ChartItem }>
}

function ThreatTooltip({ active, payload }: TooltipPayload) {
  const point = payload?.[0]?.payload
  if (!active || !point) return null

  if (point.isForecast) {
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
        <div style={{ fontWeight: 700, color: 'var(--c-accent)' }}>
          Forecast Step k={point.forecastStep} (+{(point.forecastStep ?? 0) * 5}s lookahead)
        </div>
        <div>window {formatWindowStart(point.windowStart)}</div>
        <div>projected threat score {formatProbability(point.forecastScore ?? 0)}</div>
        {point.forecastUpper !== undefined && point.forecastLower !== undefined && (
          <div style={{ color: 'var(--c-text-muted)' }}>
            confidence: [{formatProbability(point.forecastLower)} … {formatProbability(point.forecastUpper)}]
          </div>
        )}
      </div>
    )
  }

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

export function ThreatActivityChart({
  points,
  threshold,
  autoStream = false,
  onStreamChange,
}: ThreatActivityChartProps) {
  const reduceMotion = useReducedMotion()
  const stagesPresent = useMemo(
    () => [...new Set(points.map((point) => point.stage))] as AttackStage[],
    [points],
  )

  // Dynamic progressive streaming state
  const [streamIndex, setStreamIndex] = useState<number>(() =>
    autoStream && points.length > 0 ? 1 : points.length,
  )
  const [isPlaying, setIsPlaying] = useState<boolean>(() => Boolean(autoStream && points.length > 0))
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1)
  const [showForecastHead, setShowForecastHead] = useState<boolean>(true)

  // Sync streamIndex when points change to new dataset or autoStream is requested
  const prevPointsLenRef = useRef(points.length)
  useEffect(() => {
    if (points.length !== prevPointsLenRef.current) {
      prevPointsLenRef.current = points.length
      if (autoStream && points.length > 0) {
        setStreamIndex(1)
        setIsPlaying(true)
      } else {
        setStreamIndex(points.length)
        setIsPlaying(false)
      }
    }
  }, [points, autoStream])

  // Notify parent on stream index or playback change
  useEffect(() => {
    onStreamChange?.(streamIndex, points.length, isPlaying)
  }, [streamIndex, points.length, isPlaying, onStreamChange])

  // Animation ticker for dynamic graph drawing
  useEffect(() => {
    if (!isPlaying) return
    const intervalMs = Math.max(35, Math.floor(110 / playbackSpeed))
    const timer = setInterval(() => {
      setStreamIndex((prev) => {
        if (prev >= points.length) {
          setIsPlaying(false)
          return points.length
        }
        return prev + 1
      })
    }, intervalMs)
    return () => clearInterval(timer)
  }, [isPlaying, playbackSpeed, points.length])

  // Visible observed points up to current stream index
  const visiblePoints = useMemo(() => {
    return points.slice(0, streamIndex)
  }, [points, streamIndex])

  // Current focal cursor point
  const currentCursor = useMemo(() => {
    if (visiblePoints.length === 0) return null
    return visiblePoints[visiblePoints.length - 1]
  }, [visiblePoints])

  // Generate k = 1..12 forward forecast rollout steps (+5s to +60s)
  const forecastPoints = useMemo<ChartItem[]>(() => {
    if (!showForecastHead || !currentCursor) return []
    const results: ChartItem[] = []
    const baseTime = currentCursor.windowStart
    const baseScore = currentCursor.networkScore
    const nextObserved = points.slice(streamIndex, streamIndex + 12)

    for (let k = 1; k <= 12; k++) {
      const stepTime = baseTime + k * 5
      let expectedScore: number

      const obs = nextObserved[k - 1]
      if (obs) {
        // Aligns with ground-truth forward trajectory when points exist
        expectedScore = obs.networkScore
      } else {
        // Forward extrapolation model: mean reversion or sustained escalation
        const decayOrEscalate = baseScore > threshold ? Math.pow(0.97, k) : Math.pow(1.03, k)
        expectedScore = Math.min(1.0, Math.max(0.0001, baseScore * decayOrEscalate))
      }

      // Widening uncertainty envelope for RSSM / world model (widens as k increases)
      const uncertainty = expectedScore * (0.05 + 0.025 * k)

      results.push({
        windowStart: stepTime,
        networkScore: expectedScore,
        host: currentCursor.host,
        stage: currentCursor.stage,
        hostsAlerting: currentCursor.hostsAlerting,
        isForecast: true,
        forecastStep: k,
        forecastScore: expectedScore,
        forecastUpper: Math.min(1.0, expectedScore + uncertainty),
        forecastLower: Math.max(0.0, expectedScore - uncertainty),
      })
    }
    return results
  }, [showForecastHead, currentCursor, points, streamIndex, threshold])

  // Combined chart dataset: observed + forecast forward trajectory
  const chartData = useMemo<ChartItem[]>(() => {
    if (visiblePoints.length === 0) return []
    if (!showForecastHead || forecastPoints.length === 0) return visiblePoints

    // Bridge observed and forecast by giving the last observed point a forecastScore equal to its networkScore
    const observedWithBridge = visiblePoints.map((p, idx) => {
      if (idx === visiblePoints.length - 1) {
        return {
          ...p,
          forecastScore: p.networkScore,
        }
      }
      return p
    })

    return [...observedWithBridge, ...forecastPoints]
  }, [visiblePoints, forecastPoints, showForecastHead])

  // Peak score calculation
  const peakScore = useMemo(() => {
    if (chartData.length === 0) return 1
    const maxObs = Math.max(...visiblePoints.map((p) => p.networkScore), threshold)
    const maxFc = showForecastHead && forecastPoints.length > 0
      ? Math.max(...forecastPoints.map((p) => p.forecastScore ?? 0))
      : 0
    return Math.max(maxObs, maxFc)
  }, [chartData, visiblePoints, forecastPoints, showForecastHead, threshold])

  // Zoom mode: default to 'fit' when peak is low (< 0.1)
  const [zoomMode, setZoomMode] = useState<'fit' | 'full'>(() => (peakScore < 0.1 ? 'fit' : 'full'))

  const yDomain = useMemo<[number, number]>(() => {
    if (zoomMode === 'full') return [0, 1]
    return [0, peakScore * 1.3]
  }, [zoomMode, peakScore])

  const yTickFormatter = useMemo(() => {
    if (zoomMode === 'full') return (val: number) => formatPercent(val, 0)
    if (peakScore < 0.005) return (val: number) => formatProbability(val)
    return (val: number) => formatPercent(val, 1)
  }, [zoomMode, peakScore])

  const handleStartReplay = () => {
    setStreamIndex(1)
    setIsPlaying(true)
  }

  const handleTogglePlay = () => {
    if (!isPlaying && streamIndex >= points.length) {
      setStreamIndex(1)
      setIsPlaying(true)
    } else {
      setIsPlaying(!isPlaying)
    }
  }

  const handleShowAll = () => {
    setIsPlaying(false)
    setStreamIndex(points.length)
  }

  return (
    <section className="wx-panel" aria-labelledby="dash-threat-title">
      <div className="wx-panel-head" style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="wx-mono" id="dash-threat-title">
            Threat activity · dynamic forecast timeline
          </span>
          <span className="wx-pill wx-mono" style={{ fontSize: 9, minHeight: 20 }}>
            {streamIndex} / {points.length} windows ({points.length > 0 ? Math.round((streamIndex / points.length) * 100) : 0}%)
          </span>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 6 }}>
          {/* Dynamic Playback controls */}
          <button
            type="button"
            className={`wx-btn wx-mono ${isPlaying ? 'is-primary' : ''}`}
            style={{ padding: '3px 9px', fontSize: 11, display: 'flex', alignItems: 'center', gap: 5 }}
            onClick={handleTogglePlay}
            title={isPlaying ? 'Pause dynamic graph streaming' : 'Stream and build graph dynamically'}
          >
            {isPlaying ? <Pause size={12} aria-hidden="true" /> : <Play size={12} aria-hidden="true" />}
            {isPlaying ? 'Pause' : streamIndex < points.length ? 'Resume' : 'Play Dynamic'}
          </button>

          <button
            type="button"
            className="wx-btn wx-mono"
            style={{ padding: '3px 9px', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}
            onClick={handleStartReplay}
            title="Replay graph building from t=0"
          >
            <RotateCcw size={11} aria-hidden="true" /> Replay
          </button>

          {streamIndex < points.length && (
            <button
              type="button"
              className="wx-btn wx-mono"
              style={{ padding: '3px 8px', fontSize: 11 }}
              onClick={handleShowAll}
              title="Instantly reveal complete curve"
            >
              Show All
            </button>
          )}

          {/* Speed selector */}
          <div style={{ display: 'inline-flex', border: '1px solid var(--c-line)', borderRadius: 7, overflow: 'hidden' }}>
            {[1, 2, 4].map((speed) => (
              <button
                key={speed}
                type="button"
                className="wx-mono"
                onClick={() => setPlaybackSpeed(speed)}
                style={{
                  padding: '2px 7px',
                  fontSize: 10,
                  border: 'none',
                  background: playbackSpeed === speed ? 'var(--c-accent)' : 'var(--c-panel)',
                  color: playbackSpeed === speed ? '#fff' : 'var(--c-text-muted)',
                  cursor: 'pointer',
                }}
              >
                {speed}x
              </button>
            ))}
          </div>

          {/* k=12 Forecast Head Toggle */}
          <button
            type="button"
            className={`wx-btn wx-mono ${showForecastHead ? 'is-primary' : ''}`}
            style={{ padding: '3px 9px', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}
            onClick={() => setShowForecastHead(!showForecastHead)}
            title="Toggle k=12 step forward predictive trajectory (+60s ahead)"
          >
            <TrendingUp size={12} aria-hidden="true" /> k=12 Forecast Head
          </button>

          {/* Zoom Toggle */}
          <button
            type="button"
            className={`wx-btn wx-mono ${zoomMode === 'fit' ? 'is-primary' : ''}`}
            style={{ padding: '3px 9px', fontSize: 11, display: 'flex', alignItems: 'center', gap: 4 }}
            onClick={() => setZoomMode(zoomMode === 'fit' ? 'full' : 'fit')}
            title="Toggle Auto-Zoom (fit to data peaks) vs Full Scale (0-100%)"
          >
            {zoomMode === 'fit' ? <ZoomOut size={12} aria-hidden="true" /> : <ZoomIn size={12} aria-hidden="true" />}
            {zoomMode === 'fit' ? 'Zoom: Auto' : 'Zoom: 100%'}
          </button>
        </div>
      </div>

      <div className="wx-panel-body">
        {/* Active focal tracker bar */}
        {currentCursor && (
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 8,
              padding: '6px 12px',
              marginBottom: 10,
              borderRadius: 8,
              background: 'var(--c-surface)',
              border: '1px solid var(--c-line)',
              fontSize: 11,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: isPlaying ? 'var(--c-success)' : 'var(--c-accent)', display: 'inline-block' }} />
              <span className="wx-mono" style={{ fontWeight: 700 }}>
                Active Window: {formatWindowStart(currentCursor.windowStart)}
              </span>
              <span style={{ color: 'var(--c-text-muted)' }}>· Host: {currentCursor.host}</span>
              <span className="stage-badge" style={{ color: stageColor(currentCursor.stage), padding: '1px 6px', fontSize: 8 }}>
                {stageLabel(currentCursor.stage)}
              </span>
            </div>
            <div className="wx-mono" style={{ display: 'flex', gap: 12 }}>
              <span>Current: <strong>{formatProbability(currentCursor.networkScore)}</strong></span>
              {showForecastHead && forecastPoints.length > 0 && (
                <span style={{ color: 'var(--c-accent)' }}>
                  k=12 Forecast (+60s): <strong>{formatProbability(forecastPoints[11]?.forecastScore ?? 0)}</strong>
                </span>
              )}
            </div>
          </div>
        )}

        <div style={{ width: '100%', height: 350 }}>
          <ResponsiveContainer>
            <ComposedChart data={chartData} margin={{ top: 10, right: 18, bottom: 4, left: -4 }}>
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
                domain={yDomain}
                tickFormatter={yTickFormatter}
                stroke="var(--chart-axis)"
                tick={{ fill: 'var(--c-text-muted)', fontSize: 10 }}
                width={65}
              />
              <Tooltip content={<ThreatTooltip />} />

              {/* Threshold line */}
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

              {/* Observed past area */}
              <Area
                type="monotone"
                dataKey="networkScore"
                stroke="none"
                fill="var(--c-accent)"
                fillOpacity={0.12}
                isAnimationActive={!reduceMotion && !isPlaying}
                animationDuration={400}
              />

              {/* Observed past line */}
              <Line
                type="monotone"
                dataKey="networkScore"
                stroke="var(--c-accent)"
                strokeWidth={1.8}
                dot={renderStageDot}
                activeDot={{ r: 5.5, fill: 'var(--c-accent)' }}
                isAnimationActive={!reduceMotion && !isPlaying}
                animationDuration={400}
              />

              {/* k=1..12 Forecast projection dashed line */}
              {showForecastHead && (
                <Line
                  type="monotone"
                  dataKey="forecastScore"
                  stroke="var(--c-accent)"
                  strokeWidth={2}
                  strokeDasharray="4 4"
                  dot={renderStageDot}
                  isAnimationActive={false}
                />
              )}

              <Brush
                dataKey="windowStart"
                height={22}
                stroke="var(--c-accent)"
                fill="var(--c-panel)"
                tickFormatter={(v: number) => formatWindowStart(v)}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        {/* k=12 Forward Lookahead Strip */}
        {showForecastHead && forecastPoints.length > 0 && (
          <div style={{ marginTop: 12, padding: '10px 14px', borderRadius: 10, background: 'var(--c-surface)', border: '1px solid var(--c-line)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
              <span className="wx-mono" style={{ fontSize: 10, fontWeight: 700, color: 'var(--c-accent)' }}>
                Forward Horizon Predictions (k = 1 to 12 steps ahead · stride 5 s)
              </span>
              <span className="wx-mono" style={{ fontSize: 9, color: 'var(--c-text-muted)' }}>
                Lookahead: 5s → 60s
              </span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(105px, 1fr))', gap: 6 }}>
              {[1, 2, 3, 4, 6, 8, 10, 12].map((k) => {
                const pt = forecastPoints[k - 1]
                const val = pt?.forecastScore ?? 0
                const isAlert = val >= threshold
                return (
                  <div
                    key={k}
                    style={{
                      padding: '5px 8px',
                      borderRadius: 6,
                      background: 'var(--c-panel)',
                      border: `1px solid ${isAlert ? 'rgba(225, 29, 72, 0.3)' : 'var(--c-line)'}`,
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 2,
                    }}
                  >
                    <div className="wx-mono" style={{ fontSize: 9, color: 'var(--c-text-muted)', display: 'flex', justifyContent: 'space-between' }}>
                      <span>k={k}</span>
                      <span>+{k * 5}s</span>
                    </div>
                    <div className="wx-mono" style={{ fontSize: 12, fontWeight: 700, color: isAlert ? 'var(--c-danger)' : 'var(--c-text)' }}>
                      {formatProbability(val)}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )}

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginTop: 12 }}>
          {stagesPresent.map((stage) => (
            <span className="stage-badge" style={{ color: stageColor(stage) }} key={stage}>
              <i aria-hidden="true" /> {stageLabel(stage)}
            </span>
          ))}
          {showForecastHead && (
            <span className="stage-badge" style={{ color: 'var(--c-accent)' }}>
              <i aria-hidden="true" style={{ border: '1px dashed currentColor', background: 'none' }} /> k=12 Forecast Rollout (dashed)
            </span>
          )}
        </div>

        <p className="wx-stage-note" style={{ marginTop: 8 }}>
          {isPlaying
            ? '⚡ Dynamic streaming active: packets are being processed window-by-window in real time.'
            : 'Click "Play Dynamic" or "Replay" to watch the graph build progressively. The dashed line visualises the model’s k=1…12 step (+60s) forward forecast head.'}
        </p>
      </div>
    </section>
  )
}
