import { FileEdit, RotateCcw, ShieldAlert, ShieldCheck, Wand2 } from 'lucide-react'

import type { LedgerChainState } from '@/features/ledger/useLedgerChain'
import { TAMPER_PROBABILITY } from '@/lib/ledgerChain'
import { formatProbability } from '@/lib/format'

interface LedgerTamperPanelProps {
  state: LedgerChainState
  selectedIndex: number
  onSelectIndex: (index: number) => void
  onEdit: (index: number) => void
  onRewrite: (index: number) => void
  onRestore: () => void
  busy: boolean
}

/**
 * The two documented tamper modes, run for real:
 *  - edit    : set probability = 0.999999 on one record, no re-hash → verify() fails there.
 *  - rewrite : same edit, then recompute every hash → verify() passes, anchor fails.
 * Every reported boolean and index is the value we just computed, never asserted.
 */
export function LedgerTamperPanel({
  state,
  selectedIndex,
  onSelectIndex,
  onEdit,
  onRewrite,
  onRestore,
  busy,
}: LedgerTamperPanelProps) {
  const verified = state.verifyResult?.ok === true
  const anchored = state.anchorResult?.ok === true
  const count = state.entries.length
  const clean = state.tamperMode === 'none'

  return (
    <section className="wx-panel" aria-labelledby="ledger-tamper-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="ledger-tamper-title">
          Tamper demonstration
        </span>
        <span className="wx-mono">
          {clean ? 'clean chain' : state.tamperMode === 'edit' ? 'single-record edit' : 'full rewrite'}
        </span>
      </div>

      <div className="wx-panel-body">
        <div className="wx-kv" style={{ borderBottom: 0, paddingTop: 0 }}>
          <label htmlFor="tamper-index" style={{ color: 'var(--c-text-muted)' }}>
            Target record
          </label>
          <div style={{ textAlign: 'right' }}>
            <select
              id="tamper-index"
              className="wx-mono"
              value={selectedIndex}
              disabled={count === 0}
              onChange={(e) => onSelectIndex(Number(e.target.value))}
              style={{
                border: '1px solid var(--c-line)',
                borderRadius: 8,
                padding: '4px 8px',
                background: 'var(--c-panel)',
                color: 'var(--c-text)',
                fontSize: 11.5,
              }}
            >
              {state.clean.map((entry, index) => (
                <option key={entry.hash} value={index}>
                  #{String(index).padStart(2, '0')} · {entry.host} · {entry.stage}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 12 }}>
          <button
            type="button"
            className="wx-btn is-danger"
            disabled={busy || count === 0}
            onClick={() => onEdit(selectedIndex)}
          >
            <FileEdit size={14} aria-hidden="true" /> Tamper record
          </button>
          <button
            type="button"
            className="wx-btn is-danger"
            disabled={busy || count === 0}
            onClick={() => onRewrite(selectedIndex)}
          >
            <Wand2 size={14} aria-hidden="true" /> Rewrite chain
          </button>
          <button
            type="button"
            className="wx-btn"
            disabled={busy || clean}
            onClick={onRestore}
          >
            <RotateCcw size={14} aria-hidden="true" /> Restore
          </button>
        </div>

        {/* Real computed state — not a claim. */}
        <div style={{ display: 'grid', gap: 8, marginTop: 14 }}>
          <div
            className="wx-notice"
            role="status"
            style={{ borderColor: verified ? undefined : 'rgba(220,38,38,0.28)' }}
          >
            {verified ? (
              <ShieldCheck size={15} color="var(--c-success)" aria-hidden="true" />
            ) : (
              <ShieldAlert size={15} color="var(--c-danger)" aria-hidden="true" />
            )}
            <div>
              <strong>verify()</strong> ={' '}
              <span className="wx-mono">{verified ? 'true' : 'false'}</span>
              {verified
                ? ' — the hash chain recomputes cleanly from genesis.'
                : ` — first inconsistent record is index ${state.verifyResult?.firstBadIndex ?? '?'}.`}
            </div>
          </div>

          <div
            className="wx-notice"
            role="status"
            style={{ borderColor: anchored ? undefined : 'rgba(220,38,38,0.28)' }}
          >
            {anchored ? (
              <ShieldCheck size={15} color="var(--c-success)" aria-hidden="true" />
            ) : (
              <ShieldAlert size={15} color="var(--c-danger)" aria-hidden="true" />
            )}
            <div>
              <strong>verify_against_checkpoints()</strong> ={' '}
              <span className="wx-mono">{anchored ? 'true' : 'false'}</span> — anchored head{' '}
              {state.anchorResult?.headMatches ? 'matches' : 'differs'}, Merkle root{' '}
              {state.anchorResult?.rootMatches ? 'matches' : 'differs'}.
            </div>
          </div>
        </div>

        <p className="wx-stage-note" style={{ marginTop: 12 }}>
          Tampering sets <code className="wx-mono">probability = {formatProbability(TAMPER_PROBABILITY)}</code> on
          the chosen record — the same mutation <code>ledger/panels.py</code> performs. No value
          shown here is fabricated: the booleans and the failing index are recomputed by real
          SHA-256 / HMAC after each action.
        </p>
      </div>
    </section>
  )
}
