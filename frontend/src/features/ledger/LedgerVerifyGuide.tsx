import { Terminal } from 'lucide-react'

/**
 * The offline verification commands and a short explanation of what each of the
 * two documented tamper modes proves. No runtime values here — this is
 * reference material pointing at the authoritative Python verifier.
 */
export function LedgerVerifyGuide() {
  return (
    <section className="wx-panel" aria-labelledby="ledger-guide-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="ledger-guide-title">
          Offline verification
        </span>
        <span className="wx-mono">authority: Python CLI</span>
      </div>

      <div className="wx-panel-body">
        <div className="wx-notice" role="note">
          <Terminal size={15} aria-hidden="true" />
          <div style={{ display: 'grid', gap: 8 }}>
            <div>
              Recompute the hash chain and anchored checkpoints for a real run:
              <br />
              <code>python -m ledger.verify_cli run/audit_chain.jsonl</code>
            </div>
            <div>
              Verify the published weight digests:
              <br />
              <code>python scripts/verify_weights.py</code>
            </div>
          </div>
        </div>

        <dl style={{ margin: '12px 0 0' }}>
          <div className="wx-kv">
            <dt style={{ color: 'var(--c-text-muted)' }}>Single-record edit</dt>
            <dd style={{ textAlign: 'left', fontFamily: 'inherit' }}>
              Editing record <em>i</em> breaks <em>i</em>&apos;s own hash, so{' '}
              <span className="wx-mono">verify()</span> fails at exactly <em>i</em>. Proves
              per-record tamper-evidence.
            </dd>
          </div>
          <div className="wx-kv">
            <dt style={{ color: 'var(--c-text-muted)' }}>Full self-consistent rewrite</dt>
            <dd style={{ textAlign: 'left', fontFamily: 'inherit' }}>
              Recomputing every hash re-passes <span className="wx-mono">verify()</span>, but the
              chain head and Merkle root no longer match the anchored checkpoint, so{' '}
              <span className="wx-mono">verify_against_checkpoints()</span> fails. Proves the
              external anchor catches a whole-chain forgery.
            </dd>
          </div>
        </dl>
      </div>
    </section>
  )
}
