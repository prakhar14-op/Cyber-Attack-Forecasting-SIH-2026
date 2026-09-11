import { HORIZON0_FUSED_LEAD, KSTEP_OPERATING_POINT } from '@/data/projectResults'

/**
 * The operating-point reality: instead of a fake lead-vs-horizon curve, this
 * contrasts the k-step head's fixed-budget lead (0 s, 0/2) against the
 * horizon-0 fused model's actual shipped lead — each labelled with the model
 * that produced it. Source: README.md, docs/limitations.md.
 */
export function OperatingPointReality() {
  return (
    <section className="wx-panel" aria-labelledby="fc-op-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="fc-op-title">
          Lead at the fixed 1% FPR budget
        </span>
        <span className="wx-mono">by model</span>
      </div>

      <div className="wx-panel-body">
        <div className="wx-metrics" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
          <div className="wx-metric">
            <span className="wx-mono" style={{ color: 'var(--c-warn)' }}>
              {KSTEP_OPERATING_POINT.model}
            </span>
            <div className="wx-metric-value wx-num" style={{ color: 'var(--c-warn)' }}>
              {KSTEP_OPERATING_POINT.leadSeconds} s
            </div>
            <small>
              F1 {KSTEP_OPERATING_POINT.f1} · episodes {KSTEP_OPERATING_POINT.episodes} at the{' '}
              {KSTEP_OPERATING_POINT.budget} budget — the k-step head does not fire.
            </small>
          </div>

          <div className="wx-metric">
            <span className="wx-mono" style={{ color: 'var(--c-accent)' }}>
              {HORIZON0_FUSED_LEAD.model}
            </span>
            <div className="wx-metric-value wx-num" style={{ color: 'var(--c-accent)' }}>
              {HORIZON0_FUSED_LEAD.leadMedianText}
            </div>
            <small>
              episodes {HORIZON0_FUSED_LEAD.episodes} · {HORIZON0_FUSED_LEAD.perEpisodeText} at the{' '}
              {HORIZON0_FUSED_LEAD.budget} budget.
            </small>
          </div>
        </div>

        <div className="wx-notice tone-warn" style={{ marginTop: 12 }}>
          <span aria-hidden="true">!</span>
          <span>{KSTEP_OPERATING_POINT.detail}</span>
        </div>

        <div className="wx-notice" style={{ marginTop: 10 }}>
          <span aria-hidden="true">i</span>
          <span>{HORIZON0_FUSED_LEAD.detail}</span>
        </div>
      </div>
    </section>
  )
}
