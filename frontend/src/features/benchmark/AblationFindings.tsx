import { ABLATION_FINDINGS, ABLATION_SOURCE } from '@/data/projectResults'

/**
 * Ablation findings: determinism proof (identical rows), the t2v_clamped
 * collapse under determinism, and the uncorrelated-error fusion stability.
 * Source: README.md + tier1_hardening_report.md.
 */
export function AblationFindings() {
  return (
    <section className="wx-panel" aria-labelledby="bm-ablation-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="bm-ablation-title">
          Ablation &amp; determinism
        </span>
        <span className="wx-mono">why the numbers are trustworthy</span>
      </div>

      <div className="wx-panel-body">
        <ol style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 10 }}>
          {ABLATION_FINDINGS.map((finding) => (
            <li
              key={finding.slice(0, 32)}
              style={{ color: 'var(--c-text-sub)', fontSize: 12.5, lineHeight: 1.65 }}
            >
              {finding}
            </li>
          ))}
        </ol>

        <p className="wx-stage-note" style={{ marginTop: 10 }}>
          Source: {ABLATION_SOURCE}
        </p>
      </div>
    </section>
  )
}
