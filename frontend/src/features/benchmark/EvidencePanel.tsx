import { EVIDENCE_STEPS } from '@/data/projectResults'

/**
 * Evidence panel: where the numbers come from — the full provenance chain.
 * Source: README.md, docs/benchmark_protocol.md.
 */
export function EvidencePanel() {
  return (
    <section className="wx-panel" aria-labelledby="bm-evidence-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="bm-evidence-title">
          Evidence &amp; provenance
        </span>
        <span className="wx-mono">every number traces back</span>
      </div>

      <div className="wx-panel-body">
        <ul style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 9 }}>
          {EVIDENCE_STEPS.map((step) => (
            <li
              key={step.slice(0, 32)}
              className="wx-num"
              style={{ color: 'var(--c-text-sub)', fontSize: 12, lineHeight: 1.65 }}
            >
              {step}
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}
