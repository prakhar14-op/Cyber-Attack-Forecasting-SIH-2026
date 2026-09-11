import { RISK_COLOR } from '@/features/graph/graphTheme'
import type { GraphModel } from '@/features/graph/graphModel'
import { formatProbability } from '@/lib/format'

/**
 * The scene must be readable without relying on colour: shape carries the
 * internal/external distinction and every band is labelled with the numeric
 * rule that defines it.
 */
export function GraphLegend({ model, threshold }: { model: GraphModel; threshold: number }) {
  return (
    <div className="graph-legend">
      <h3>Risk band · peak probability</h3>
      <div className="graph-legend-row" style={{ color: RISK_COLOR.high }}>
        <span className="graph-legend-swatch shape-sphere" />
        <span>high · ≥ {formatProbability(model.highBand)} ({model.counts.high})</span>
      </div>
      <div className="graph-legend-row" style={{ color: RISK_COLOR.alerting }}>
        <span className="graph-legend-swatch shape-sphere" />
        <span>alerting · ≥ {formatProbability(threshold)} ({model.counts.alerting})</span>
      </div>
      <div className="graph-legend-row" style={{ color: RISK_COLOR.quiet }}>
        <span className="graph-legend-swatch shape-sphere" />
        <span>no alert on this host ({model.counts.quiet})</span>
      </div>

      <h3 style={{ marginTop: 8 }}>Shape · host zone</h3>
      <div className="graph-legend-row" style={{ color: '#cbd5e1' }}>
        <span className="graph-legend-swatch shape-sphere" />
        <span>internal</span>
      </div>
      <div className="graph-legend-row" style={{ color: '#cbd5e1' }}>
        <span className="graph-legend-swatch shape-box" />
        <span>external ({model.counts.external})</span>
      </div>
      <div className="graph-legend-row" style={{ color: '#cbd5e1' }}>
        <span className="graph-legend-swatch shape-octa" />
        <span>zone not derived</span>
      </div>

      <h3 style={{ marginTop: 8 }}>Edges</h3>
      <div className="graph-legend-row" style={{ color: '#ef4444' }}>
        <span className="graph-legend-swatch" style={{ height: 2, border: 0, background: 'currentColor' }} />
        <span>from an alerting source host</span>
      </div>
      <div className="graph-legend-row" style={{ color: '#64748b' }}>
        <span className="graph-legend-swatch" style={{ height: 2, border: 0, background: 'currentColor' }} />
        <span>flow relationship · brightness = weight</span>
      </div>
    </div>
  )
}
