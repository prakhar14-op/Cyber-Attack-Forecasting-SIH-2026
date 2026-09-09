import { lazy, Suspense } from 'react'
import { Activity, Crosshair, Radar, Waypoints } from 'lucide-react'
import { motion } from 'motion/react'

const LandingNetworkScene = lazy(() => import('@/components/graph/LandingNetworkScene'))

const horizonSteps = ['t', '+1', '+2', '+4', '+8'] as const

export function HeroNetworkVisual() {
  return (
    <motion.div
      className="lp-visual-shell"
      initial={{ opacity: 0, x: 28, scale: 0.98 }}
      animate={{ opacity: 1, x: 0, scale: 1 }}
      transition={{ delay: 0.16, duration: 0.75, ease: [0.22, 1, 0.36, 1] }}
    >
      <div className="lp-visual-frame">
        <div className="lp-corner lp-corner-tl" />
        <div className="lp-corner lp-corner-tr" />
        <div className="lp-corner lp-corner-bl" />
        <div className="lp-corner lp-corner-br" />
        <div className="lp-visual-grid" aria-hidden="true" />
        <Suspense fallback={<div className="lp-network-loading">INITIALIZING SIGNAL MAP</div>}>
          <LandingNetworkScene />
        </Suspense>

        <div className="lp-visual-topline">
          <span><i /> Conceptual signal map</span>
          <span>NO CAPTURE LOADED</span>
        </div>

        <div className="lp-stage-axis" aria-hidden="true">
          <span>NETWORK</span><b /><span>SIGNAL</span><b /><span>THREAT</span><b /><span>FORECAST</span>
        </div>

        <div className="lp-float-panel lp-panel-threat">
          <div className="lp-panel-label"><Crosshair size={12} /> Threat signal</div>
          <div className="lp-readout-row"><span>Host probability</span><strong>Awaiting input</strong></div>
          <div className="lp-signal-track"><i /></div>
          <small>Per source host · 15 s window</small>
        </div>

        <div className="lp-float-panel lp-panel-forecast">
          <div className="lp-panel-label"><Radar size={12} /> Forecast vector</div>
          <div className="lp-horizon-row">
            {horizonSteps.map((step, index) => <span key={step} className={index === 4 ? 'is-horizon' : ''}>{step}</span>)}
          </div>
          <small>8 windows · up to 40 s ahead</small>
        </div>

        <div className="lp-model-evidence-strip">
          <span>MODEL EVIDENCE</span>
          <strong>Named features · contributing windows</strong>
          <small>NO EMBEDDING DIMENSIONS</small>
        </div>

        <div className="lp-node-key">
          <span><i className="normal" /> host</span>
          <span><i className="threat" /> threat path</span>
          <span><Waypoints size={11} /> ambient preview</span>
        </div>

        <div className="lp-visual-watermark"><Activity size={13} /> SIGNAL SPACE / IDLE</div>
      </div>
    </motion.div>
  )
}
