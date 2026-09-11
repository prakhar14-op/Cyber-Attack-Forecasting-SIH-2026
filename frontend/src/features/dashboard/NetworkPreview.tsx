import { ArrowRight, Network } from 'lucide-react'
import { Link } from 'react-router'

import type { NetworkPreview as NetworkPreviewData } from '@/features/dashboard/dashboardSelectors'
import { formatInt, formatPercent } from '@/lib/format'

const VIEW_W = 840
const VIEW_H = 360

/** Risk drives radius; alerting hosts are marked, not just coloured. */
function nodeRadius(peakProb: number, degree: number): number {
  return 6 + peakProb * 9 + Math.min(degree / 400, 1) * 3
}

export function NetworkPreview({ preview }: { preview: NetworkPreviewData }) {
  const riskiest = preview.nodes[0]

  return (
    <section className="wx-panel" aria-labelledby="dash-net-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="dash-net-title">
          Network threat map · preview
        </span>
        <span className="wx-mono">
          {preview.shown} of {preview.total} hosts
          {preview.truncated ? ' · trimmed by risk' : ''}
        </span>
      </div>

      <div className="wx-panel-body">
        <div className="dash-net">
          <svg
            viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
            role="img"
            aria-label={`Host communication preview: ${preview.shown} hosts, ${preview.edges.length} flow relationships${
              riskiest ? `, highest risk ${riskiest.ip}` : ''
            }`}
          >
            {preview.edges.map((edge) => (
              <line
                key={`${edge.src}->${edge.dst}`}
                x1={edge.x0 * VIEW_W}
                y1={edge.y0 * VIEW_H}
                x2={edge.x1 * VIEW_W}
                y2={edge.y1 * VIEW_H}
                stroke={edge.risk > 0 ? 'var(--c-danger)' : 'var(--c-text-muted)'}
                strokeOpacity={edge.risk > 0 ? 0.45 : 0.3}
                strokeWidth={edge.risk > 0 ? 1.5 : 1}
              />
            ))}

            {preview.nodes.map((node) => {
              const alerting = node.alerts > 0
              return (
                <g key={node.ip}>
                  <circle
                    cx={node.x * VIEW_W}
                    cy={node.y * VIEW_H}
                    r={nodeRadius(node.peakProb, node.degree)}
                    fill={alerting ? 'var(--c-danger)' : 'var(--c-panel)'}
                    fillOpacity={alerting ? 0.16 : 1}
                    stroke={alerting ? 'var(--c-danger)' : 'var(--c-text-muted)'}
                    strokeWidth={alerting ? 1.6 : 1}
                  />
                  <text
                    x={node.x * VIEW_W}
                    y={node.y * VIEW_H + nodeRadius(node.peakProb, node.degree) + 13}
                    textAnchor="middle"
                    fontFamily="SFMono-Regular, Consolas, monospace"
                    fontSize={10}
                    fill={alerting ? 'var(--c-danger)' : 'var(--c-text-sub)'}
                  >
                    {node.ip}
                  </text>
                  {alerting && (
                    <text
                      x={node.x * VIEW_W}
                      y={node.y * VIEW_H + 3.5}
                      textAnchor="middle"
                      fontFamily="SFMono-Regular, Consolas, monospace"
                      fontSize={9}
                      fontWeight={700}
                      fill="#991b1b"
                    >
                      {formatPercent(node.peakProb, 0)}
                    </text>
                  )}
                </g>
              )
            })}
          </svg>
        </div>

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 10,
            marginTop: 12,
          }}
        >
          <span className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
            {formatInt(preview.edges.length)} flow relationships · red = alerting source host
          </span>
          <Link className="wx-btn" to="/graph">
            <Network size={14} aria-hidden="true" /> Open Attack Graph{' '}
            <ArrowRight size={14} aria-hidden="true" />
          </Link>
        </div>

        {preview.truncated && (
          <p className="wx-stage-note" style={{ marginTop: 8 }}>
            Trimmed to the {preview.shown} highest-risk hosts for readability. The full graph keeps
            every node.
          </p>
        )}
      </div>
    </section>
  )
}
