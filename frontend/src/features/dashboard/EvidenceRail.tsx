import { Activity, ArrowRight, Binary, ChartNoAxesCombined, Radar, ScrollText } from 'lucide-react'
import { Link } from 'react-router'

const LINKS = [
  {
    to: '/timeline',
    icon: Activity,
    label: 'Timeline',
    note: 'replay the capture and read the lead time',
  },
  {
    to: '/explain',
    icon: Binary,
    label: 'Explainability',
    note: 'how the model decides, and what it cannot do',
  },
  {
    to: '/forecast',
    icon: Radar,
    label: 'Forecast horizons',
    note: 't+1 … t+8 ranking, stated honestly',
  },
  {
    to: '/ledger',
    icon: ScrollText,
    label: 'Audit ledger',
    note: 'verify, tamper, re-verify',
  },
  {
    to: '/benchmark',
    icon: ChartNoAxesCombined,
    label: 'Benchmark',
    note: 'model comparison and limitations',
  },
] as const

/** Where to go after triage. Keeps the dashboard the hub of the workflow. */
export function EvidenceRail() {
  return (
    <section className="wx-panel" aria-labelledby="dash-rail-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="dash-rail-title">
          Continue the investigation
        </span>
        <span className="wx-mono">evidence · integrity · evaluation</span>
      </div>
      <div
        className="wx-panel-body"
        style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 8 }}
      >
        {LINKS.map((link) => (
          <Link key={link.to} className="wx-row" to={link.to} style={{ textDecoration: 'none' }}>
            <span className="wx-row-icon" aria-hidden="true">
              <link.icon size={16} strokeWidth={1.8} />
            </span>
            <span>
              <strong>{link.label}</strong>
              <small>{link.note}</small>
            </span>
            <ArrowRight size={14} aria-hidden="true" style={{ color: 'var(--c-text-muted)' }} />
          </Link>
        ))}
      </div>
    </section>
  )
}
