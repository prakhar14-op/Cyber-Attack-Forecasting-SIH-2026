import {
  Binary,
  Braces,
  FileInput,
  Fingerprint,
  Radar,
  ScrollText,
} from 'lucide-react'
import { motion } from 'motion/react'

const pipeline = [
  { id: '01', label: 'PCAP / Flow', note: 'file input', icon: FileInput },
  { id: '02', label: 'Feature extraction', note: 'named signals', icon: Braces },
  { id: '03', label: 'Temporal intelligence', note: 'causal context', icon: Binary },
  { id: '04', label: 'Forecast', note: 't+1 … t+8', icon: Radar },
  { id: '05', label: 'Explanation', note: 'feature evidence', icon: Fingerprint },
  { id: '06', label: 'Ledger', note: 'tamper evident', icon: ScrollText },
] as const

export function ForecastPipeline() {
  return (
    <section className="lp-section lp-pipeline-section" id="intelligence">
      <div className="lp-pipeline-heading">
        <div>
          <span className="lp-kicker">02 / How it forecasts</span>
          <h2>From captured traffic to an <em>auditable warning.</em></h2>
        </div>
        <p>One causal path. Every stage keeps the forecast connected to observable network evidence.</p>
      </div>

      <div className="lp-pipeline-track">
        <div className="lp-pipeline-line" aria-hidden="true"><i /></div>
        {pipeline.map((stage, index) => (
          <motion.div
            className="lp-pipeline-stage"
            key={stage.id}
            initial={{ opacity: 0, y: 18 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-70px' }}
            transition={{ delay: index * 0.08, duration: 0.45 }}
          >
            <div className="lp-stage-node">
              <stage.icon size={18} />
              <span>{stage.id}</span>
            </div>
            <strong>{stage.label}</strong>
            <small>{stage.note}</small>
          </motion.div>
        ))}
      </div>

      <div className="lp-pipeline-readout">
        <div><span>UNIT</span><strong>(source host, window)</strong></div>
        <div><span>CONTEXT</span><strong>causal · no future leakage</strong></div>
        <div><span>DECISION</span><strong>threshold from FPR budget</strong></div>
        <div><span>OUTPUT</span><strong>forecast + evidence + proof</strong></div>
      </div>
    </section>
  )
}
