import { useState } from 'react'
import { CheckCircle2, Link2, ShieldAlert, ShieldCheck } from 'lucide-react'

import type { LedgerChainState } from '@/features/ledger/useLedgerChain'
import { formatInt } from '@/lib/format'

function abbreviate(hex: string, head = 10, tail = 6): string {
  if (hex.length <= head + tail + 1) return hex
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`
}

/**
 * Top metric strip. Every value here is computed at runtime from the real
 * chain — record count, the actual verify() boolean, the actual anchored
 * (head + Merkle) booleans, and the recomputed Merkle root.
 */
export function LedgerMetrics({ state }: { state: LedgerChainState }) {
  const [showRoot, setShowRoot] = useState(false)

  const verified = state.verifyResult?.ok === true
  const anchored = state.anchorResult?.ok === true
  const root = state.anchorResult?.merkleRoot ?? ''

  return (
    <div className="wx-metrics" style={{ marginTop: 16 }}>
      <div className="wx-metric">
        <span className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          Records in chain
        </span>
        <div className="wx-metric-value wx-num">{formatInt(state.entries.length)}</div>
        <small>one leaf per forecast, in engine append order</small>
      </div>

      <div className="wx-metric">
        <span className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          Hash-chain verify
        </span>
        <div
          className="wx-metric-value"
          style={{
            color: verified ? 'var(--c-success)' : 'var(--c-danger)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          {verified ? (
            <>
              <ShieldCheck size={22} aria-hidden="true" /> Pass
            </>
          ) : (
            <>
              <ShieldAlert size={22} aria-hidden="true" /> Fail
            </>
          )}
        </div>
        <small>
          {verified
            ? 'recomputed from genesis, every link consistent'
            : `first inconsistent record: index ${state.verifyResult?.firstBadIndex ?? '?'}`}
        </small>
      </div>

      <div className="wx-metric">
        <span className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          Anchored checkpoint
        </span>
        <div
          className="wx-metric-value"
          style={{
            color: anchored ? 'var(--c-success)' : 'var(--c-danger)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          {anchored ? (
            <>
              <Link2 size={22} aria-hidden="true" /> Match
            </>
          ) : (
            <>
              <ShieldAlert size={22} aria-hidden="true" /> Mismatch
            </>
          )}
        </div>
        <small>
          head {state.anchorResult?.headMatches ? 'ok' : 'differs'} · merkle{' '}
          {state.anchorResult?.rootMatches ? 'ok' : 'differs'}
        </small>
      </div>

      <div className="wx-metric">
        <span className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
          Merkle root
        </span>
        <div
          className="wx-metric-value wx-mono"
          style={{ fontSize: '0.95rem', wordBreak: 'break-all', lineHeight: 1.4 }}
          title={root}
        >
          {showRoot ? root : abbreviate(root)}
        </div>
        <button
          type="button"
          className="wx-btn wx-mono"
          style={{ minHeight: 28, marginTop: 6, padding: '0 10px', fontSize: 11 }}
          onClick={() => setShowRoot((v) => !v)}
        >
          <CheckCircle2 size={12} aria-hidden="true" />
          {showRoot ? 'Abbreviate' : 'Show full 64-hex'}
        </button>
      </div>
    </div>
  )
}
