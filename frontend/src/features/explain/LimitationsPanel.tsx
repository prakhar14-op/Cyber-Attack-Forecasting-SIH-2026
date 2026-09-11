import { AlertTriangle } from 'lucide-react'

import { LIMITATIONS } from '@/data/modelArtifacts'

export function LimitationsPanel() {
  return (
    <section className="wx-panel" aria-labelledby="explain-limits-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="explain-limits-title">
          Limitations &amp; confidence
        </span>
        <span className="wx-pill wx-mono tone-danger">
          <AlertTriangle size={12} aria-hidden="true" /> read before trusting a number
        </span>
      </div>

      <div className="wx-panel-body" style={{ display: 'grid', gap: 10 }}>
        {LIMITATIONS.map((limitation) => (
          <div className={`wx-notice tone-${limitation.tone}`} role="note" key={limitation.title}>
            <AlertTriangle size={15} aria-hidden="true" />
            <div>
              <div style={{ fontWeight: 700, marginBottom: 3 }}>{limitation.title}</div>
              <div>{limitation.body}</div>
              <div
                className="wx-mono"
                style={{ marginTop: 6, fontSize: 10, color: 'var(--c-text-muted)' }}
              >
                source: {limitation.sources.join(' · ')}
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}
