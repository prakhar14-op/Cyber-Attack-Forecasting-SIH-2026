import type { GraphModel } from '@/features/graph/graphModel'
import { EDGE_COLOR, RISK_COLOR, SCENE_BACKGROUND } from '@/features/graph/graphTheme'

const W = 900
const H = 520

/**
 * Static 2D rendering of the same model, used when WebGL is unavailable or the
 * analyst prefers reduced motion. Same shape and colour semantics as the 3D
 * scene: circle = internal, square = external, diamond = unknown.
 */
export function Graph2DFallback({
  model,
  selected,
  onSelect,
  replay,
}: {
  model: GraphModel
  selected: string | null
  onSelect: (ip: string | null) => void
  replay: {
    activeHosts: Set<string>
    seenHosts: Set<string>
    stageByHost: Map<string, string>
  } | null
}) {
  // Reserve room on the right while the inspector is open so nodes stay visible.
  const insetRight = selected ? 330 : 60
  const xs = model.nodes.map((node) => node.x)
  const ys = model.nodes.map((node) => node.y)
  const minX = Math.min(...xs, -1)
  const maxX = Math.max(...xs, 1)
  const minY = Math.min(...ys, -1)
  const maxY = Math.max(...ys, 1)

  const px = (x: number) => 60 + ((x - minX) / (maxX - minX || 1)) * (W - 60 - insetRight)
  const py = (y: number) => H - 60 - ((y - minY) / (maxY - minY || 1)) * (H - 120)

  return (
    <svg
      className="graph-fallback"
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label={`Host graph: ${model.shown} hosts, ${model.edges.length} flow relationships, ${model.counts.high} high risk`}
      onClick={() => onSelect(null)}
    >
      <rect width={W} height={H} fill={SCENE_BACKGROUND} />
      {model.edges.map((edge) => {
        const active = replay ? replay.activeHosts.has(edge.src) : null
        return (
          <line
            key={`${edge.src}->${edge.dst}`}
            x1={px(edge.from.x)}
            y1={py(edge.from.y)}
            x2={px(edge.to.x)}
            y2={py(edge.to.y)}
            stroke={edge.risk > 0 ? EDGE_COLOR.risky : EDGE_COLOR.quiet}
            strokeOpacity={active === null ? (edge.risk > 0 ? 0.7 : 0.5) : active ? 0.95 : 0.14}
            strokeWidth={active ? 2 : edge.risk > 0 ? 1.6 : 1}
          />
        )
      })}

      {model.nodes.map((node) => {
        const size = 6 + node.peakProb * 9
        const color = RISK_COLOR[node.risk]
        const isSelected = node.ip === selected
        const active = replay?.activeHosts.has(node.ip) ?? false
        const seen = replay?.seenHosts.has(node.ip) ?? false
        const dimmed = replay !== null && !active && !seen
        const stageRing = replay?.stageByHost.get(node.ip) ?? null
        const cx = px(node.x)
        const cy = py(node.y)
        return (
          <g
            key={node.ip}
            style={{ cursor: 'pointer', opacity: dimmed ? 0.22 : 1 }}
            onClick={(event) => {
              event.stopPropagation()
              onSelect(node.ip)
            }}
          >
            {isSelected && <circle cx={cx} cy={cy} r={size + 7} fill="none" stroke="#38bdf8" strokeWidth={1.4} />}
            {active && stageRing && (
              <circle cx={cx} cy={cy} r={size + 4} fill="none" stroke={stageRing} strokeWidth={2} />
            )}
            {node.zone === 'internal' ? (
              <circle cx={cx} cy={cy} r={size} fill={color} fillOpacity={0.28} stroke={color} strokeWidth={1.5} />
            ) : node.zone === 'external' ? (
              <rect
                x={cx - size}
                y={cy - size}
                width={size * 2}
                height={size * 2}
                fill={color}
                fillOpacity={0.28}
                stroke={color}
                strokeWidth={1.5}
              />
            ) : (
              <rect
                x={cx - size}
                y={cy - size}
                width={size * 2}
                height={size * 2}
                transform={`rotate(45 ${cx} ${cy})`}
                fill={color}
                fillOpacity={0.28}
                stroke={color}
                strokeWidth={1.5}
              />
            )}
            <text
              x={cx}
              y={cy + size + 14}
              textAnchor="middle"
              fontFamily="SFMono-Regular, Consolas, monospace"
              fontSize={10}
              fill={node.risk === 'quiet' ? '#94a3b8' : '#fecaca'}
            >
              {node.ip}
              {node.alerts > 0 ? ` · ${(node.peakProb * 100).toFixed(0)}%` : ''}
            </text>
          </g>
        )
      })}
    </svg>
  )
}
