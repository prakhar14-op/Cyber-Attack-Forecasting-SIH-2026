import { useCallback, useMemo, useRef } from 'react'

import type { ReplayModel } from '@/features/timeline/timelineModel'
import { formatProbability, formatSeconds, formatWindowStart } from '@/lib/format'
import { stageHex, stageLabel } from '@/lib/stages'

const W = 1200
const H = 300
const PAD_L = 54
const PAD_R = 18
const PAD_T = 40
const PAD_B = 46
const STRIDE_SECONDS = 5

interface ReplayTrackProps {
  model: ReplayModel
  cursor: number | null
  /** Zoomed viewport in capture seconds. */
  view: { start: number; end: number }
  threshold: number
  onSeek: (time: number) => void
}

export function ReplayTrack({ model, cursor, view, threshold, onSeek }: ReplayTrackProps) {
  const svg = useRef<SVGSVGElement>(null)
  const dragging = useRef(false)

  const span = Math.max(view.end - view.start, STRIDE_SECONDS)
  const plotW = W - PAD_L - PAD_R
  const plotH = H - PAD_T - PAD_B

  const x = useCallback((time: number) => PAD_L + ((time - view.start) / span) * plotW, [plotW, span, view.start])
  const y = useCallback((score: number) => PAD_T + (1 - score) * plotH, [plotH])

  const seekFromEvent = useCallback(
    (clientX: number) => {
      const element = svg.current
      if (!element) return
      const bounds = element.getBoundingClientRect()
      const ratio = (clientX - bounds.left) / bounds.width
      const svgX = ratio * W
      const time = view.start + ((svgX - PAD_L) / plotW) * span
      onSeek(time)
    },
    [onSeek, plotW, span, view.start],
  )

  const ticks = useMemo(() => {
    const count = 6
    return Array.from({ length: count + 1 }, (_, index) => view.start + (span * index) / count)
  }, [span, view.start])

  const bandY = PAD_T - 26
  const visibleWindows = model.windows.filter(
    (window) => window.end >= view.start && window.start <= view.end,
  )

  return (
    <div
      className="replay-track"
      onPointerDown={(event) => {
        dragging.current = true
        event.currentTarget.setPointerCapture(event.pointerId)
        seekFromEvent(event.clientX)
      }}
      onPointerMove={(event) => {
        if (dragging.current) seekFromEvent(event.clientX)
      }}
      onPointerUp={(event) => {
        dragging.current = false
        event.currentTarget.releasePointerCapture(event.pointerId)
      }}
    >
      <svg ref={svg} viewBox={`0 0 ${W} ${H}`} role="presentation">
        {/* plot frame */}
        <rect x={PAD_L} y={PAD_T} width={plotW} height={plotH} fill="#0e1728" />
        {[0.25, 0.5, 0.75].map((level) => (
          <line
            key={level}
            x1={PAD_L}
            x2={PAD_L + plotW}
            y1={y(level)}
            y2={y(level)}
            stroke="rgba(148,163,184,.12)"
          />
        ))}
        {[0, 0.5, 1].map((level) => (
          <text
            key={level}
            x={PAD_L - 9}
            y={y(level) + 3}
            textAnchor="end"
            fontFamily="SFMono-Regular, Consolas, monospace"
            fontSize={9}
            fill="#64748b"
          >
            {(level * 100).toFixed(0)}%
          </text>
        ))}

        {/* annotated episode bands — ground truth, from the operator log */}
        {model.episodes.map((episode) => {
          const left = Math.max(x(episode.start), PAD_L)
          const right = Math.min(x(episode.end), PAD_L + plotW)
          if (right <= left) return null
          const color = stageHex(episode.stage)
          return (
            <g key={`${episode.name}-${episode.start}`}>
              <rect
                x={left}
                y={PAD_T}
                width={right - left}
                height={plotH}
                fill={color}
                fillOpacity={episode.stage === 'benign' ? 0.03 : 0.07}
              />
              <rect x={left} y={bandY} width={right - left} height={8} fill={color} fillOpacity={0.7} rx={2} />
              {right - left > 62 && (
                <text
                  x={left + 4}
                  y={bandY - 4}
                  fontFamily="SFMono-Regular, Consolas, monospace"
                  fontSize={8.5}
                  fill={color}
                >
                  {stageLabel(episode.stage).toUpperCase()}
                </text>
              )}
            </g>
          )
        })}

        {/* threshold */}
        <line
          x1={PAD_L}
          x2={PAD_L + plotW}
          y1={y(threshold)}
          y2={y(threshold)}
          stroke="#f87171"
          strokeDasharray="5 4"
        />
        <text
          x={PAD_L + plotW - 4}
          y={y(threshold) - 5}
          textAnchor="end"
          fontFamily="SFMono-Regular, Consolas, monospace"
          fontSize={9}
          fill="#f87171"
        >
          threshold {formatProbability(threshold)}
        </text>

        {/* one bar per scored alert window */}
        {visibleWindows.map((window) => {
          const left = x(window.start)
          const width = Math.max((STRIDE_SECONDS / span) * plotW - 1, 1.5)
          const top = y(window.score)
          const isCurrent =
            cursor !== null && cursor >= window.start && cursor < window.start + STRIDE_SECONDS
          return (
            <rect
              key={window.start}
              x={left}
              y={top}
              width={width}
              height={PAD_T + plotH - top}
              fill={stageHex(window.stage)}
              fillOpacity={isCurrent ? 1 : 0.62}
              stroke={isCurrent ? '#e2e8f0' : 'none'}
              strokeWidth={isCurrent ? 0.8 : 0}
            />
          )
        })}

        {/* lead-time bracket: first alert -> annotated completion */}
        {model.firstAlert && model.completion !== null && (
          <g>
            <line
              x1={x(model.firstAlert.time)}
              x2={x(model.completion)}
              y1={PAD_T + plotH + 16}
              y2={PAD_T + plotH + 16}
              stroke="#38bdf8"
              strokeWidth={1.4}
            />
            <line
              x1={x(model.firstAlert.time)}
              x2={x(model.firstAlert.time)}
              y1={PAD_T + plotH + 11}
              y2={PAD_T + plotH + 21}
              stroke="#38bdf8"
              strokeWidth={1.4}
            />
            <line
              x1={x(model.completion)}
              x2={x(model.completion)}
              y1={PAD_T + plotH + 11}
              y2={PAD_T + plotH + 21}
              stroke="#38bdf8"
              strokeWidth={1.4}
            />
            <text
              x={(x(model.firstAlert.time) + x(model.completion)) / 2}
              y={PAD_T + plotH + 34}
              textAnchor="middle"
              fontFamily="SFMono-Regular, Consolas, monospace"
              fontSize={10}
              fill="#7dd3fc"
            >
              FIRST ALERT → LAST COMPLETION {formatSeconds(model.completion - model.firstAlert.time)}
            </text>
          </g>
        )}

        {/* first alert */}
        {model.firstAlert && (
          <g>
            <line
              x1={x(model.firstAlert.time)}
              x2={x(model.firstAlert.time)}
              y1={PAD_T}
              y2={PAD_T + plotH}
              stroke="#38bdf8"
              strokeWidth={1.2}
            />
            <text
              x={x(model.firstAlert.time) + 5}
              y={PAD_T + 13}
              fontFamily="SFMono-Regular, Consolas, monospace"
              fontSize={9}
              fill="#7dd3fc"
            >
              FIRST ALERT {formatWindowStart(model.firstAlert.time)}
            </text>
          </g>
        )}

        {/* earliest contributing window */}
        {model.earliestEvidence && (
          <line
            x1={x(model.earliestEvidence.time)}
            x2={x(model.earliestEvidence.time)}
            y1={PAD_T}
            y2={PAD_T + plotH}
            stroke="#a78bfa"
            strokeDasharray="3 3"
            strokeWidth={1}
          />
        )}

        {/* annotated completion */}
        {model.completion !== null && (
          <g>
            <line
              x1={x(model.completion)}
              x2={x(model.completion)}
              y1={PAD_T}
              y2={PAD_T + plotH}
              stroke="#f87171"
              strokeWidth={1.2}
            />
            <text
              x={x(model.completion) - 5}
              y={PAD_T + 13}
              textAnchor="end"
              fontFamily="SFMono-Regular, Consolas, monospace"
              fontSize={9}
              fill="#fca5a5"
            >
              COMPLETION {formatWindowStart(model.completion)}
            </text>
          </g>
        )}

        {/* time axis */}
        {ticks.map((tick) => (
          <text
            key={tick}
            x={x(tick)}
            y={H - 8}
            textAnchor="middle"
            fontFamily="SFMono-Regular, Consolas, monospace"
            fontSize={9}
            fill="#64748b"
          >
            {formatWindowStart(tick)}
          </text>
        ))}

        {/* cursor */}
        {cursor !== null && cursor >= view.start && cursor <= view.end && (
          <g>
            <line
              x1={x(cursor)}
              x2={x(cursor)}
              y1={bandY - 10}
              y2={PAD_T + plotH + 6}
              stroke="#f8fafc"
              strokeWidth={1.4}
            />
            <circle cx={x(cursor)} cy={bandY - 10} r={4} fill="#f8fafc" />
          </g>
        )}
      </svg>
    </div>
  )
}
