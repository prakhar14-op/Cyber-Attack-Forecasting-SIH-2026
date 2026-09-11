import { ArrowRight, ScanSearch } from 'lucide-react'
import { Link } from 'react-router'

export function DashboardEmptyState() {
  return (
    <section className="wx-panel dash-empty" aria-labelledby="dash-empty-title">
      <div style={{ maxWidth: 460 }}>
        <div className="wx-drop-icon" style={{ margin: '0 auto' }} aria-hidden="true">
          <ScanSearch size={20} strokeWidth={1.8} />
        </div>
        <h2 id="dash-empty-title" style={{ margin: '16px 0 8px', fontSize: 20, fontWeight: 740 }}>
          Load a capture to begin analysis
        </h2>
        <p style={{ margin: '0 0 18px', color: 'var(--c-text-sub)', fontSize: 13, lineHeight: 1.7 }}>
          The dashboard reads one completed analysis. Nothing is shown until a capture has actually
          been through the pipeline — there are no placeholder alerts, hosts or scores here.
        </p>
        <Link className="wx-btn is-primary" to="/analyze">
          Analyze a capture <ArrowRight size={15} aria-hidden="true" />
        </Link>
      </div>
    </section>
  )
}
