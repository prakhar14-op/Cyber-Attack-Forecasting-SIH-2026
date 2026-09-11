import { OPERATING_POINT } from '@/data/projectResults'

/**
 * Operating point panel: how the threshold is chosen and the deployed engine
 * variants' validation AUROC. Source: docs/limitations.md §3, README.md,
 * docs/benchmark_protocol.md.
 */
export function OperatingPointPanel() {
  return (
    <section className="wx-panel" aria-labelledby="bm-op-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="bm-op-title">
          Operating point &amp; threshold
        </span>
        <span className="wx-mono">{OPERATING_POINT.thresholdSource}</span>
      </div>

      <div className="wx-panel-body">
        <div className="wx-metrics" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <div className="wx-metric">
            <span className="wx-mono">val AUROC · flow-only</span>
            <div className="wx-metric-value wx-num">
              {OPERATING_POINT.valAurocFlowOnly.toFixed(3)}
            </div>
            <small>deployed engine variant (docs/limitations.md §3)</small>
          </div>
          <div className="wx-metric">
            <span className="wx-mono">val AUROC · full</span>
            <div className="wx-metric-value wx-num">{OPERATING_POINT.valAurocFull.toFixed(3)}</div>
            <small>deployed engine variant (docs/limitations.md §3)</small>
          </div>
        </div>

        <div className="wx-notice" style={{ marginTop: 12 }}>
          <span aria-hidden="true">i</span>
          <span>{OPERATING_POINT.detail}</span>
        </div>

        <div className="wx-notice" style={{ marginTop: 10 }}>
          <span aria-hidden="true">i</span>
          <span>{OPERATING_POINT.splits}</span>
        </div>
      </div>
    </section>
  )
}
