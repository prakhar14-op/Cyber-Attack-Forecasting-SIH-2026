import { ArrowRight, Cpu, Database, LockKeyhole, Network, ShieldCheck, WifiOff } from 'lucide-react'
import { motion } from 'motion/react'
import { Link } from 'react-router'

import { BrandMark } from '@/components/ui/BrandMark'
import { Panel } from '@/components/ui/Panel'
import { StatusBadge } from '@/components/ui/StatusBadge'
import { workflowSteps } from '@/lib/navigation'

const systemRows = [
  { label: 'Interface shell', value: 'Ready', color: 'var(--success)', icon: ShieldCheck },
  { label: 'Python engine', value: 'Not connected', color: 'var(--text-muted)', icon: Cpu },
  { label: 'Data source', value: 'Awaiting capture', color: 'var(--warning)', icon: Database },
  { label: 'Runtime policy', value: 'Local only', color: 'var(--accent)', icon: WifiOff },
] as const

const productFacts = [
  { value: '15 s', label: 'Host window' },
  { value: '40 s', label: 'Forecast horizon' },
  { value: '7', label: 'ATT&CK stages' },
] as const

export default function LandingPage() {
  return (
    <div className="landing-page">
      <div className="landing-orbit" aria-hidden="true" />

      <nav className="landing-nav" aria-label="Landing navigation">
        <BrandMark />
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <Link className="secondary-button" to="/benchmark">Evaluation</Link>
          <Link className="primary-button" to="/analyze">
            Enter console <ArrowRight size={15} />
          </Link>
        </div>
      </nav>

      <main className="landing-hero">
        <motion.section
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55, ease: [0.2, 0.8, 0.2, 1] }}
        >
          <StatusBadge tone="success" pulse>Offline early-warning system</StatusBadge>
          <h1 className="landing-title">
            See the attack <span className="gradient-text">before impact.</span>
          </h1>
          <p className="landing-copy">
            A forensic SOC workspace for host-level network attack forecasting, named-feature evidence and tamper-evident decisions — designed to run without the internet.
          </p>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginTop: 30 }}>
            <Link className="primary-button" to="/analyze">
              Analyze a capture <ArrowRight size={15} />
            </Link>
            <Link className="secondary-button" to="/dashboard">
              Preview workspace
            </Link>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 32, marginTop: 48 }}>
            {productFacts.map((fact) => (
              <div key={fact.label}>
                <div className="tabular" style={{ fontSize: 20, fontWeight: 760, letterSpacing: '-0.04em' }}>{fact.value}</div>
                <div className="mono-label" style={{ marginTop: 5, color: 'var(--text-muted)', fontSize: 8 }}>{fact.label}</div>
              </div>
            ))}
          </div>
        </motion.section>

        <motion.div
          initial={{ opacity: 0, x: 18 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.12, duration: 0.55, ease: [0.2, 0.8, 0.2, 1] }}
        >
          <Panel className="landing-console">
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 14 }}>
              <div>
                <div className="mono-label" style={{ color: 'var(--accent)', fontSize: 9 }}>System posture</div>
                <div style={{ marginTop: 5, fontSize: 18, fontWeight: 740 }}>Analyst console</div>
              </div>
              <LockKeyhole size={18} color="var(--success)" />
            </div>

            {systemRows.map((row) => (
              <div className="console-row" key={row.label}>
                <row.icon size={15} color={row.color} />
                <span style={{ color: 'var(--text-sub)', fontSize: 12 }}>{row.label}</span>
                <span className="mono-label" style={{ color: row.color, fontSize: 8 }}>{row.value}</span>
              </div>
            ))}

            <div style={{ position: 'relative', display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 6, marginTop: 20 }}>
              {workflowSteps.map((step, index) => (
                <div key={step.label} style={{ textAlign: 'center' }}>
                  <div
                    style={{
                      display: 'grid',
                      width: 34,
                      height: 34,
                      margin: '0 auto 8px',
                      placeItems: 'center',
                      border: '1px solid var(--border-medium)',
                      borderRadius: 10,
                      background: index === 0 ? 'var(--accent-dim)' : 'rgba(5,12,24,.3)',
                      color: index === 0 ? 'var(--accent)' : 'var(--text-muted)',
                    }}
                  >
                    <step.icon size={15} />
                  </div>
                  <span className="mono-label" style={{ color: 'var(--text-muted)', fontSize: 7 }}>{step.label}</span>
                </div>
              ))}
            </div>
          </Panel>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '13px 0 0 8px', color: 'var(--text-muted)', fontSize: 10 }}>
            <Network size={13} /> Flagship host/attack graph reserved for the visualization phase
          </div>
        </motion.div>
      </main>
    </div>
  )
}
