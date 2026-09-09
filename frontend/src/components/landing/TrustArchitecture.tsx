import { Check, Cpu, Fingerprint, KeyRound, Link2, ShieldCheck, WifiOff } from 'lucide-react'
import { motion } from 'motion/react'

const offlineChecks = [
  ['Cloud APIs', 'disabled'],
  ['Runtime downloads', 'disabled'],
  ['Telemetry', 'disabled'],
  ['Inference', 'local'],
  ['Ledger verify', 'local'],
] as const

const proofChain = [
  { label: 'Forecast', note: 'host · window · stage', icon: Cpu },
  { label: 'Evidence', note: 'named features', icon: Fingerprint },
  { label: 'Model digest', note: 'SHA-256 provenance', icon: KeyRound },
  { label: 'Chain + Merkle', note: 'offline verification', icon: Link2 },
] as const

export function TrustArchitecture() {
  return (
    <section className="lp-section lp-trust-section" id="architecture">
      <div className="lp-offline-console">
        <div className="lp-offline-topbar">
          <span><i /> LOCAL EXECUTION POLICY</span>
          <WifiOff size={15} />
        </div>
        <div className="lp-offline-body">
          <div className="lp-offline-emblem">
            <div><WifiOff size={29} /></div>
            <span>NETWORK EGRESS</span>
            <strong>NOT REQUIRED</strong>
          </div>
          <div className="lp-offline-checks">
            {offlineChecks.map(([label, state]) => (
              <div key={label}><span>{label}</span><strong><Check size={11} />{state}</strong></div>
            ))}
          </div>
        </div>
        <div className="lp-terminal-line"><span>$</span> verify --capture ./evidence.pcap --offline <i /></div>
      </div>

      <div className="lp-trust-copy">
        <span className="lp-kicker">04 / Why the result can be trusted</span>
        <h2>Evidence first. <em>Integrity always.</em></h2>
        <p>Every warning stays tied to named network features, the exact model artefact and an append-only audit record that can be checked without a remote service.</p>
        <div className="lp-proof-chain">
          {proofChain.map((item, index) => (
            <motion.div
              className="lp-proof-item"
              key={item.label}
              initial={{ opacity: 0, x: 16 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.1 }}
            >
              <div><item.icon size={15} /></div>
              <span><strong>{item.label}</strong><small>{item.note}</small></span>
              {index < proofChain.length - 1 && <i />}
            </motion.div>
          ))}
        </div>
        <div className="lp-integrity-note"><ShieldCheck size={15} /> Editing one record breaks verification at the exact index.</div>
      </div>
    </section>
  )
}
