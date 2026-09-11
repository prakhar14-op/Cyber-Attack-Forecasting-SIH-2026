import { ArrowRight, Link2, ShieldCheck, ShieldX } from 'lucide-react'
import { motion, useReducedMotion } from 'motion/react'

import { formatInt, formatProbability } from '@/lib/format'
import type { LedgerStatus, RunSummary } from '@/types/backend'

interface CompletionSummaryProps {
  summary: RunSummary
  ledger: LedgerStatus | null
  /** Seconds left before the console advances on its own; null = no auto-advance. */
  autoAdvanceIn: number | null
  onContinue: () => void
  onStay: () => void
}

export function CompletionSummary({
  summary,
  ledger,
  autoAdvanceIn,
  onContinue,
  onStay,
}: CompletionSummaryProps) {
  const reduceMotion = useReducedMotion()
  const verified = ledger?.verified === true

  return (
    <motion.section
      className="wx-panel"
      initial={reduceMotion ? false : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      aria-labelledby="wx-summary-title"
    >
      <div className="wx-panel-head">
        <span className="wx-mono" id="wx-summary-title">
          Run complete
        </span>
        <span className="wx-mono">
          fpr budget {summary.fpr_budget * 100}% · window 15 s · stride 5 s
        </span>
      </div>

      <div className="wx-panel-body" style={{ display: 'grid', gap: 14 }}>
        <div className="wx-metrics">
          <div className="wx-metric">
            <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
              Flows
            </div>
            <div className="wx-metric-value">{formatInt(summary.n_flows)}</div>
            <small>parsed from the capture</small>
          </div>
          <div className="wx-metric">
            <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
              Host windows
            </div>
            <div className="wx-metric-value">{formatInt(summary.n_host_windows)}</div>
            <small>scored (source host, window) rows</small>
          </div>
          <div className="wx-metric">
            <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
              Alerts
            </div>
            <div className="wx-metric-value" style={{ color: 'var(--c-accent)' }}>
              {formatInt(summary.n_alerts)}
            </div>
            <small>windows above threshold</small>
          </div>
          <div className="wx-metric">
            <div className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
              Threshold
            </div>
            <div className="wx-metric-value">{formatProbability(summary.threshold)}</div>
            <small>from the validation split</small>
          </div>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          <span className={`wx-pill wx-mono ${verified ? 'tone-ok' : 'tone-danger'}`}>
            {verified ? <ShieldCheck size={12} aria-hidden="true" /> : <ShieldX size={12} aria-hidden="true" />}
            Ledger {verified ? 'verified' : 'not verified'}
          </span>
          <span className="wx-pill wx-mono">
            {formatInt(ledger?.records ?? 0)} chained records
          </span>
          <span className={`wx-pill wx-mono ${ledger?.anchored ? 'tone-ok' : 'tone-warn'}`}>
            <Link2 size={12} aria-hidden="true" />
            {ledger?.anchored ? 'Merkle checkpoint anchored' : 'checkpoint not anchored'}
          </span>
        </div>

        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: 10,
            paddingTop: 12,
            borderTop: '1px solid var(--c-line)',
          }}
        >
          <button type="button" className="wx-btn is-primary" onClick={onContinue}>
            Open SOC Dashboard <ArrowRight size={15} aria-hidden="true" />
          </button>

          {autoAdvanceIn !== null && (
            <>
              <span className="wx-mono" style={{ color: 'var(--c-text-muted)' }} role="status">
                opening in {autoAdvanceIn.toFixed(1)} s
              </span>
              <button type="button" className="wx-btn" onClick={onStay}>
                Stay on this page
              </button>
            </>
          )}
        </div>
      </div>
    </motion.section>
  )
}
