import { ArrowDown, ArrowRight, ChevronRight, CircleDot, RadioTower, ShieldCheck } from 'lucide-react'
import { motion } from 'motion/react'
import { Link } from 'react-router'

import { EarlyWarningTimeline } from '@/components/landing/EarlyWarningTimeline'
import { ForecastPipeline } from '@/components/landing/ForecastPipeline'
import { HeroNetworkVisual } from '@/components/landing/HeroNetworkVisual'
import { LandingNavbar } from '@/components/landing/LandingNavbar'
import { SystemVision } from '@/components/landing/SystemVision'
import { TrustArchitecture } from '@/components/landing/TrustArchitecture'
import { BrandMark } from '@/components/ui/BrandMark'
import '@/styles/landing.css'

const proofMetrics = [
  { value: '15 s', label: 'host window' },
  { value: '8', label: 'forecast steps' },
  { value: '7', label: 'attack stages' },
  { value: 'local', label: 'offline runtime' },
] as const

export default function LandingPage() {
  return (
    <div className="lp-page">
      <LandingNavbar />

      <main>
        <section className="lp-hero" id="overview">
          <div className="lp-hero-ambient" aria-hidden="true" />
          <div className="lp-hero-grid" aria-hidden="true" />
          <div className="lp-hero-content">
            <motion.div
              className="lp-hero-copy"
              initial={{ opacity: 0, y: 24 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.65, ease: [0.22, 1, 0.36, 1] }}
            >
              <div className="lp-system-label">
                <span><i /> SIH26153</span>
                <b />
                <span>Offline early warning</span>
              </div>

              <h1 className="lp-hero-title">
                <span>See the attack</span>
                <em>before impact.</em>
              </h1>

              <p className="lp-hero-description">
                Turn network traffic into host-level warning, attack-stage intelligence and evidence an analyst can defend.
              </p>

              <div className="lp-hero-actions">
                <Link className="lp-primary-cta" to="/analyze">
                  Launch console <ArrowRight size={16} />
                </Link>
                <a className="lp-secondary-cta" href="#intelligence">
                  Explore intelligence <ArrowDown size={15} />
                </a>
              </div>

              <div className="lp-proof-metrics" aria-label="Product configuration">
                {proofMetrics.map((metric) => (
                  <div key={metric.label}>
                    <strong>{metric.value}</strong>
                    <span>{metric.label}</span>
                  </div>
                ))}
              </div>
            </motion.div>

            <HeroNetworkVisual />
          </div>

          <div className="lp-hero-footer">
            <div><RadioTower size={13} /><span>NETWORK → SIGNAL → THREAT → FORECAST</span></div>
            <div className="lp-hero-ticker">
              <span>FLOW + PACKET FEATURES</span><i />
              <span>CAUSAL WINDOWS</span><i />
              <span>NAMED EVIDENCE</span><i />
              <span>TAMPER-EVIDENT LEDGER</span>
            </div>
            <a href="#technology" aria-label="Continue to system overview"><ChevronRight size={15} /></a>
          </div>
        </section>

        <SystemVision />
        <ForecastPipeline />
        <EarlyWarningTimeline />
        <TrustArchitecture />

        <section className="lp-final-section">
          <div className="lp-final-grid" aria-hidden="true" />
          <div className="lp-final-orbit" aria-hidden="true"><CircleDot size={20} /></div>
          <motion.div
            className="lp-final-content"
            initial={{ opacity: 0, y: 24 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-80px' }}
            transition={{ duration: 0.65 }}
          >
            <span className="lp-kicker">05 / Analyst ready</span>
            <h2>Turn network traffic<br /><em>into advance warning.</em></h2>
            <p>Bring a PCAP or flow CSV. Keep the analysis, explanation and verification on your machine.</p>
            <Link className="lp-primary-cta" to="/analyze">
              Launch console <ArrowRight size={17} />
            </Link>
          </motion.div>
          <div className="lp-final-status">
            <ShieldCheck size={14} /> LOCAL · EXPLAINABLE · VERIFIABLE
          </div>
        </section>
      </main>

      <footer className="lp-footer">
        <BrandMark />
        <p>Network Attack Forecasting · SIH 2026 · Problem SIH26153</p>
        <a href="#overview">Return to signal <ArrowRight size={13} /></a>
      </footer>
    </div>
  )
}
