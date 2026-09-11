import { FileCheck2, ShieldCheck } from 'lucide-react'

/**
 * Model / weight provenance. These SHA-256 digests are PUBLISHED in the repo
 * README.md (the GitHub Release digests) — they are NOT computed by this page.
 * The engine refuses to write ledger records on a digest mismatch
 * (engine/predict.py, M9.3), so a ledger entry can never claim provenance it
 * does not have. Verify locally with `python scripts/verify_weights.py`.
 */
const WEIGHT_DIGESTS: ReadonlyArray<{ artefact: string; sha256: string }> = [
  { artefact: 'engine_model.json', sha256: '10f5873af8bda8758c2a78c859738d978620f3bd25508d66cd4daba77f2dfdc7' },
  { artefact: 'engine_model_flow.json', sha256: 'b263d7aca6b5ae1414733e26b2d4ccb71dccdf35c241c78a9b1112e516840462' },
  { artefact: 'tgn_encoder.pt', sha256: '964575cd9bebc27fedb7fb33d63dee642171e9f3e380c7735e9ae572be44c31a' },
  { artefact: 'graft.pt', sha256: '28cc45d6316a50495dbd6a324d37b70b5a7eafb8dc8f989166de2ddd378df4b1' },
  { artefact: 'window_scaler.pkl', sha256: '5fa868fc75237310987df16c7c290593584c7daa410a5a60d69ee489a4d97292' },
]

export function LedgerProvenancePanel() {
  return (
    <section className="wx-panel" aria-labelledby="ledger-provenance-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="ledger-provenance-title">
          Model &amp; weight provenance
        </span>
        <span className="wx-mono">SHA-256</span>
      </div>

      <div className="wx-panel-body">
        <div className="wx-notice tone-warn" role="note">
          <FileCheck2 size={15} aria-hidden="true" />
          <div>
            Published in <code>README.md</code>, verified by{' '}
            <code>python scripts/verify_weights.py</code>. These are the published GitHub Release
            digests — <strong>not</strong> values this page computed.
          </div>
        </div>

        <dl style={{ margin: '12px 0 0' }}>
          {WEIGHT_DIGESTS.map((row) => (
            <div className="wx-kv wx-mono" key={row.artefact}>
              <dt style={{ color: 'var(--c-text)' }}>{row.artefact}</dt>
              <dd title={row.sha256}>
                {row.sha256.slice(0, 12)}…{row.sha256.slice(-8)}
              </dd>
            </div>
          ))}
        </dl>

        <p className="wx-stage-note" style={{ marginTop: 12 }}>
          <ShieldCheck size={12} aria-hidden="true" /> The engine refuses to write ledger records on
          a digest mismatch (<code>engine/predict.py</code>, M9.3), so a ledger entry can never
          claim provenance it does not have.
        </p>
      </div>
    </section>
  )
}
