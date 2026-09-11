import { FlaskConical, Link2, RefreshCw, ShieldCheck, ShieldX } from 'lucide-react'
import { Link } from 'react-router'

import { formatBytes } from '@/lib/format'
import type { CompletedAnalysis } from '@/services/analysisSessionContext'

/** Which capture the whole dashboard is describing, and how much to trust it. */
export function CaptureContextBar({ session }: { session: CompletedAnalysis }) {
  const verified = session.ledger?.verified === true

  return (
    <div className="dash-context">
      <div className="dash-context-meta">
        <span className="wx-pill wx-mono tone-info">
          capture · {session.input.name}
        </span>
        <span className="wx-pill wx-mono">
          {formatBytes(session.input.bytes)} · {session.input.kind.toUpperCase()} ·{' '}
          {session.input.engine_variant === 'full' ? 'full features' : 'flow-only'}
        </span>
        <span className="wx-pill wx-mono">fpr budget {session.fprBudget * 100}%</span>
        <span className={`wx-pill wx-mono ${verified ? 'tone-ok' : 'tone-danger'}`}>
          {verified ? <ShieldCheck size={12} aria-hidden="true" /> : <ShieldX size={12} aria-hidden="true" />}
          ledger {verified ? 'verified' : 'unverified'}
        </span>
        {session.ledger?.anchored && (
          <span className="wx-pill wx-mono tone-ok">
            <Link2 size={12} aria-hidden="true" /> merkle anchored
          </span>
        )}
        {session.isFixture && (
          <span className="wx-pill wx-mono tone-warn">
            <FlaskConical size={12} aria-hidden="true" /> demo fixture — not engine output
          </span>
        )}
      </div>

      <Link className="wx-btn" to="/analyze">
        <RefreshCw size={14} aria-hidden="true" /> Analyse another capture
      </Link>
    </div>
  )
}
