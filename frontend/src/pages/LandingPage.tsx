import { DotLottieReact } from '@lottiefiles/dotlottie-react'
import { ArrowRight, CheckCircle, Radio, Shield, Sparkles } from 'lucide-react'
import { motion } from 'motion/react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router'

import cyberLottie from '@/assets/reference-landing/cyber-security.lottie'
import dataSecurityLottie from '@/assets/reference-landing/data-security.lottie'
import securityLottie from '@/assets/reference-landing/security.lottie'
import { EarlyWarningTimeline } from '@/components/landing/EarlyWarningTimeline'
import { ForecastPipeline } from '@/components/landing/ForecastPipeline'
import { SystemVision } from '@/components/landing/SystemVision'
import { TrustArchitecture } from '@/components/landing/TrustArchitecture'
import CardSwap, { Card } from '@/components/landing/reference/CardSwap'
import FlipWords from '@/components/landing/reference/FlipWords'
import RippleGrid from '@/components/landing/reference/RippleGrid'
import '@/styles/reference-landing.css'

type MenuItem = { title: string; desc: string; href: string }

function NavItem({ label, items }: { label: string; items: MenuItem[] }) {
  const [open, setOpen] = useState(false)
  return <div className="ref-nav-item" onMouseEnter={() => setOpen(true)} onMouseLeave={() => setOpen(false)}>
    <button>{label}<motion.span animate={{ rotate: open ? 180 : 0 }}>▾</motion.span></button>
    {open && <motion.div className="ref-dropdown" initial={{ opacity: 0, y: 8, scale: .96 }} animate={{ opacity: 1, y: 0, scale: 1 }}>
      {items.map(item => <a key={item.title} href={item.href}><strong>{item.title}</strong><small>{item.desc}</small></a>)}
    </motion.div>}
  </div>
}

const cards = [
  { badge: 'HOST-WINDOW RISK', color: '#10B981', title: 'Source-host forecasting', lines: ['15 second observation window', 'Validation-derived alert threshold', 'Network score = max host risk'] },
  { badge: 'ATT&CK STAGE', color: '#3B82F6', title: 'Attack progression', lines: ['Recon → initial access', 'Lateral movement → C2', 'Exfiltration → impact'] },
  { badge: 'FORECAST HEAD', color: '#F59E0B', title: 'Forward risk ranking', lines: ['t+1 … t+8 windows', 'Up to 40 seconds ahead', 'Causal temporal context'] },
  { badge: 'NAMED EVIDENCE', color: '#8B5CF6', title: 'Explain every warning', lines: ['Real packet and flow features', 'Contributing windows', 'MITRE technique mapping'] },
  { badge: 'AUDIT LEDGER', color: '#06B6D4', title: 'Offline verification', lines: ['Hash-chained records', 'Merkle checkpoints', 'Model SHA-256 provenance'] },
] as const

function PreviewCard({ card }: { card: typeof cards[number] }) {
  return <div className="ref-preview-card">
    <div className="ref-card-badge"><i style={{ background: card.color }} />{card.badge}</div>
    <h3>{card.title}</h3>
    <div className="ref-card-body">{card.lines.map((line, index) => <div key={line}><span style={{ color: card.color }}>{String(index + 1).padStart(2, '0')}</span><p>{line}</p><CheckCircle size={14} color={card.color} /></div>)}</div>
    <small>SIH26153 · NETWORK ATTACK FORECASTING</small>
  </div>
}

export default function LandingPage() {
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => { const handler = () => setScrolled(window.scrollY > 24); window.addEventListener('scroll', handler, { passive: true }); return () => window.removeEventListener('scroll', handler) }, [])
  return <div className="ref-page">
    <motion.nav className={scrolled ? 'ref-navbar is-scrolled' : 'ref-navbar'} initial={{ y: -80, opacity: 0 }} animate={{ y: 0, opacity: 1 }}>
      <div className="ref-nav-inner">
        <a className="ref-logo" href="#top"><span><Shield size={17} /></span><b>SENTINEL</b><em>’26</em></a>
        <div className="ref-nav-center">
          <NavItem label="Product" items={[{ title: 'Early Warning', desc: 'Host-level precursor detection', href: '#features' }, { title: 'Named Evidence', desc: 'Explainable alert decisions', href: '#pipeline' }, { title: 'Audit Ledger', desc: 'Tamper-evident offline records', href: '#architecture' }]} />
          <NavItem label="Technology" items={[{ title: 'Flow + Packet Features', desc: 'Window-bounded network evidence', href: '#features' }, { title: 'Temporal Graph', desc: 'Host relationship intelligence', href: '#pipeline' }, { title: 'Forecast Head', desc: 'Risk ranking up to t+8', href: '#pipeline' }]} />
          <NavItem label="Intelligence" items={[{ title: 'Host Triage', desc: 'Rank the hosts that need attention', href: '#features' }, { title: 'Attack Timeline', desc: 'See where the attack formed', href: '#warning' }, { title: 'MITRE Mapping', desc: 'Connect evidence to techniques', href: '#architecture' }]} />
          <a className="ref-architecture-link" href="#architecture">Architecture</a>
        </div>
        <Link className="ref-nav-cta" to="/analyze">Console <ArrowRight size={14} /></Link>
      </div>
    </motion.nav>

    <section className="ref-hero-wrap" id="top">
      <div className="ref-hero">
        <div className="ref-orb orb-a" /><div className="ref-orb orb-b" />
        <RippleGrid rows={14} cols={28} cellSize={52} color="147,197,253" />
        <div className="ref-hero-grid">
          <motion.div className="ref-hero-copy" initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }}>
            <div className="ref-hackathon-badge"><Sparkles size={12} /> SIH 2026 · NTRO · SIH26153</div>
            <h1>Network Attack<br /><FlipWords words={['Forecasting', 'Intelligence', 'Early Warning', 'Evidence']} interval={2600} /></h1>
            <p>Analyze network traffic, surface suspicious source hosts, forecast attack progression, explain every warning and verify the result completely offline.</p>
            <div className="ref-hero-actions"><Link to="/analyze">Launch Console <ArrowRight size={16} /></Link><a href="#features">Explore Platform</a></div>
          </motion.div>

          <motion.div className="ref-lottie-grid" initial={{ opacity: 0, scale: .9 }} animate={{ opacity: 1, scale: 1 }}>
            <div className="ref-lottie-tall"><DotLottieReact src={securityLottie} loop autoplay /></div>
            <div><DotLottieReact src={dataSecurityLottie} loop autoplay /></div>
            <div><DotLottieReact src={cyberLottie} loop autoplay /></div>
          </motion.div>

          <motion.div className="ref-card-stack" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
            <CardSwap width={400} height={300} cardDistance={50} verticalDistance={60} delay={4500} pauseOnHover skewAmount={5}>
              {cards.map(card => <Card key={card.badge}><PreviewCard card={card} /></Card>)}
            </CardSwap>
          </motion.div>
        </div>
        <div className="ref-hero-stats">
          {[{ val: '15 s', label: 'Host Window', badge: 'Causal Observation', icon: Shield }, { val: '40 s', label: 'Forecast Horizon', badge: 'Forward Ranking', icon: CheckCircle }, { val: 'LOCAL', label: 'Verification', badge: 'Offline by Design', icon: Radio }].map(stat => <div key={stat.label}><span><stat.icon size={20} /></span><p><b>{stat.badge}</b><small>{stat.label}: <strong>{stat.val}</strong></small></p></div>)}
        </div>
      </div>
    </section>

    <div id="features" className="ref-white-section"><SystemVision /></div>
    <div id="pipeline" className="ref-white-section"><ForecastPipeline /></div>
    <div id="warning" className="ref-white-section"><EarlyWarningTimeline /></div>
    <div id="architecture" className="ref-white-section"><TrustArchitecture /></div>

    <section className="ref-final-cta"><img src="/network-analysis.svg" alt="" /><div><span>OFFLINE · EXPLAINABLE · VERIFIABLE</span><h2>Turn network traffic<br />into advance warning.</h2><Link to="/analyze">Launch Console <ArrowRight size={17} /></Link></div></section>
    <footer className="ref-footer"><div><Shield size={16} /> <b>SENTINEL</b><span>· Network Attack Forecasting</span></div><p>SIH 2026 · Problem SIH26153 · NTRO</p></footer>
  </div>
}
