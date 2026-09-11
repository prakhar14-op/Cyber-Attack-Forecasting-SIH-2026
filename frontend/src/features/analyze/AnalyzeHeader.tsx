import { Cpu, HardDrive, WifiOff } from 'lucide-react'

export function AnalyzeHeader() {
  return (
    <header className="wx-header">
      <div>
        <span className="wx-mono wx-kicker">Operations / 01 · capture intake</span>
        <h1>Analyze Capture</h1>
        <p>
          Run the offline forecasting pipeline over a packet capture or a flow CSV. Feature
          extraction, host-window scoring, explanation and the audit ledger all execute on this
          machine — no capture data, model or metric ever leaves it.
        </p>
      </div>
      <div className="wx-header-status">
        <span className="wx-pill tone-ok wx-mono">
          <WifiOff size={12} aria-hidden="true" /> Offline · local
        </span>
        <span className="wx-pill wx-mono">
          <HardDrive size={12} aria-hidden="true" /> No network egress
        </span>
        <span className="wx-pill wx-mono">
          <Cpu size={12} aria-hidden="true" /> Batch execution
        </span>
      </div>
    </header>
  )
}
