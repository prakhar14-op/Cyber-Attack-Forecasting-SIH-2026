import { STRIDE_SECONDS, WINDOW_SECONDS } from '@/data/projectResults'

/**
 * Interpretation panel: explains what a horizon means and states plainly the
 * two honesty caveats — ranking AUROC is not per-event live confidence, and
 * evaluation performance is not a production detection guarantee.
 * Source: README.md, docs/limitations.md.
 */
export function InterpretationPanel() {
  return (
    <section className="wx-panel" aria-labelledby="fc-interp-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="fc-interp-title">
          Interpretation
        </span>
        <span className="wx-mono">read before quoting a number</span>
      </div>

      <div className="wx-panel-body">
        <dl style={{ margin: 0 }}>
          <div className="wx-kv">
            <dt>What a horizon is</dt>
            <dd style={{ textAlign: 'left' }}>
              k windows ahead. Windows are {WINDOW_SECONDS} s wide on a {STRIDE_SECONDS} s stride, so
              k = 1…8 means {STRIDE_SECONDS}…{STRIDE_SECONDS * 8} s ahead.
            </dd>
          </div>
          <div className="wx-kv">
            <dt>Overlap</dt>
            <dd style={{ textAlign: 'left' }}>
              {WINDOW_SECONDS} s windows overlap on a {STRIDE_SECONDS} s stride, so window t and t+3
              are the first fully disjoint pair. k=1 and k=2 are near-nowcasts; k=4 and k=8 are the
              honest forecasting horizons. 20 s ahead is the supported horizon; at 40 s the ranking
              holds but the val-fitted threshold stops transferring and episode detection drops to
              0/2.
            </dd>
          </div>
        </dl>

        <div className="wx-notice tone-warn" style={{ marginTop: 12 }}>
          <span aria-hidden="true">!</span>
          <span>
            Ranking quality (AUROC) is <strong>not</strong> a per-event live confidence. A high
            AUROC means the head orders windows well by risk; it does not calibrate a firing
            probability for any single window.
          </span>
        </div>

        <div className="wx-notice tone-warn" style={{ marginTop: 10 }}>
          <span aria-hidden="true">!</span>
          <span>
            Evaluation performance is <strong>not</strong> a production detection guarantee. These
            AUROC values are measured on a held-out test split; the fixed-budget operating point of
            the k-step head does not fire, so it is not a deployable forward detector as shipped.
          </span>
        </div>
      </div>
    </section>
  )
}
