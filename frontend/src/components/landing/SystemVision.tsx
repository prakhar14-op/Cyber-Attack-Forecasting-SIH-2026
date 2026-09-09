import { Braces, Network, ScanLine, Waves } from 'lucide-react'
import { motion } from 'motion/react'

const signalLayers = [
  { index: '01', label: 'Flow behavior', detail: 'bytes · packets · duration · flags', icon: Waves },
  { index: '02', label: 'Packet structure', detail: 'TTL · TCP window · payload bins', icon: Braces },
  { index: '03', label: 'Host relationships', detail: 'source → destination topology', icon: Network },
  { index: '04', label: 'Scan signatures', detail: 'ports · entropy · retransmissions', icon: ScanLine },
] as const

export function SystemVision() {
  return (
    <section className="lp-section lp-sees-section" id="technology">
      <div className="lp-section-heading">
        <span className="lp-kicker">01 / What the system sees</span>
        <h2>Traffic becomes a temporal <em>signal field.</em></h2>
        <p>Not a single suspicious packet. A changing relationship between hosts, windows and network behavior.</p>
      </div>

      <div className="lp-sees-layout">
        <div className="lp-sensor-field">
          <div className="lp-sensor-grid" aria-hidden="true" />
          <div className="lp-scan-plane" aria-hidden="true" />
          <div className="lp-sensor-core">
            <div className="lp-core-ring ring-a" />
            <div className="lp-core-ring ring-b" />
            <div className="lp-core-node"><Network size={22} /></div>
          </div>
          {['FLOW', 'PACKET', 'HOST', 'TIME'].map((label, index) => (
            <div className={`lp-sensor-tag tag-${index + 1}`} key={label}><i />{label}</div>
          ))}
          <div className="lp-sensor-caption">
            <span>OBSERVATION WINDOW</span>
            <strong>Strictly bounded · causal</strong>
          </div>
        </div>

        <div className="lp-signal-list">
          {signalLayers.map((layer, index) => (
            <motion.div
              className="lp-signal-item"
              key={layer.label}
              initial={{ opacity: 0, x: 22 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true, margin: '-80px' }}
              transition={{ delay: index * 0.08, duration: 0.45 }}
            >
              <span className="lp-signal-index">{layer.index}</span>
              <layer.icon size={18} />
              <div><strong>{layer.label}</strong><small>{layer.detail}</small></div>
              <i className="lp-signal-state" />
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  )
}
