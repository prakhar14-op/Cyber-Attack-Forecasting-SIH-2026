import { LIMITATIONS, LIMITATIONS_SOURCE } from '@/data/projectResults'

/**
 * Prominent limitations panel — first-class content for the ML reviewer, not
 * a footnote. Source: README.md + docs/limitations.md +
 * tier1_hardening_report.md → Limitations & Confidence.
 */
export function LimitationsPanel() {
  return (
    <section className="wx-panel" aria-labelledby="bm-limits-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="bm-limits-title">
          Limitations &amp; confidence
        </span>
        <span className="wx-mono">read with every number</span>
      </div>

      <div className="wx-panel-body">
        <div className="wx-notice tone-warn" style={{ marginBottom: 12 }}>
          <span aria-hidden="true">!</span>
          <span>
            These constraints qualify every metric on this page. They are stated as first-class
            content, not footnotes.
          </span>
        </div>

        <ul style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 9 }}>
          {LIMITATIONS.map((item) => (
            <li
              key={item.slice(0, 32)}
              style={{ color: 'var(--c-text-sub)', fontSize: 12.5, lineHeight: 1.65 }}
            >
              {item}
            </li>
          ))}
        </ul>

        <p className="wx-stage-note" style={{ marginTop: 10 }}>
          Source: {LIMITATIONS_SOURCE}
        </p>
      </div>
    </section>
  )
}
