import { BellRing, Flag, ScanSearch } from 'lucide-react'
import { motion } from 'motion/react'

const timelinePoints = [
  { label: 'Normal', note: 'baseline traffic', position: '5%', tone: 'normal' },
  { label: 'Anomaly', note: 'precursor forms', position: '25%', tone: 'anomaly' },
  { label: 'First alert', note: 'host crosses budget', position: '45%', tone: 'alert' },
  { label: 'Forecast', note: 'forward risk ranked', position: '66%', tone: 'forecast' },
  { label: 'Attack completion', note: 'annotated event', position: '93%', tone: 'completion' },
] as const

export function EarlyWarningTimeline() {
  return (
    <section className="lp-section lp-warning-section">
      <div className="lp-warning-copy">
        <span className="lp-kicker">03 / Why early warning matters</span>
        <h2>The useful alert happens <em>before</em> the outcome.</h2>
        <p>Success is lead time at a fixed false-positive budget — not a classifier recognizing an attack after the damage is complete.</p>
        <div className="lp-warning-principles">
          <div><ScanSearch size={15} /><span>Detect precursor behavior</span></div>
          <div><BellRing size={15} /><span>Prioritize the attacking host</span></div>
          <div><Flag size={15} /><span>Measure time gained</span></div>
        </div>
      </div>

      <div className="lp-timeline-visual">
        <div className="lp-timeline-header"><span>ATTACK EPISODE / CONCEPTUAL VIEW</span><strong>TIME →</strong></div>
        <div className="lp-timeline-chart">
          <div className="lp-timeline-base" />
          <motion.div
            className="lp-timeline-progress"
            initial={{ scaleX: 0 }}
            whileInView={{ scaleX: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 1.25, ease: [0.22, 1, 0.36, 1] }}
          />
          <div className="lp-lead-window"><span>LEAD-TIME WINDOW</span></div>
          {timelinePoints.map((point) => (
            <div className={`lp-timeline-point tone-${point.tone}`} style={{ left: point.position }} key={point.label}>
              <i />
              <strong>{point.label}</strong>
              <small>{point.note}</small>
            </div>
          ))}
          <div className="lp-forecast-cone" aria-hidden="true" />
        </div>
        <div className="lp-timeline-footer">
          <span>first actionable signal</span>
          <span>time available to investigate and contain</span>
          <span>completion</span>
        </div>
      </div>
    </section>
  )
}
