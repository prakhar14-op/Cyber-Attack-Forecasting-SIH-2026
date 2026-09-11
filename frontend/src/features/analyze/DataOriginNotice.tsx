import { FlaskConical } from 'lucide-react'

/**
 * Every screen that renders fixture values must say so. This is the one place
 * that wording lives, so it can be deleted in a single edit when the local
 * engine service replaces the demo engine.
 */
export function DataOriginNotice() {
  return (
    <div className="wx-notice tone-warn" role="note">
      <FlaskConical size={15} aria-hidden="true" />
      <div>
        <strong className="wx-mono" style={{ display: 'block', marginBottom: 4 }}>
          Demo fixture — not engine output
        </strong>
        This build ships the UI only. Runs are paced locally and the numbers below come from a
        bundled fixture shaped exactly like the result of{' '}
        <code>engine/predict.py :: predict_file</code>. Feature names, stages and MITRE techniques
        are the real ones; the probabilities, counts and threshold are placeholders until the
        local engine service is connected.
      </div>
    </div>
  )
}
