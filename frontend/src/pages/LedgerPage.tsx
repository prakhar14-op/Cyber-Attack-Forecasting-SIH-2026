import { useMemo, useState } from 'react'
import { AlertTriangle, FlaskConical, Loader2 } from 'lucide-react'

import { DashboardEmptyState } from '@/features/dashboard/DashboardEmptyState'
import { LedgerChainView } from '@/features/ledger/LedgerChainView'
import { LedgerMetrics } from '@/features/ledger/LedgerMetrics'
import { LedgerProvenancePanel } from '@/features/ledger/LedgerProvenancePanel'
import { LedgerTamperPanel } from '@/features/ledger/LedgerTamperPanel'
import { LedgerVerifyGuide } from '@/features/ledger/LedgerVerifyGuide'
import { useLedgerChain } from '@/features/ledger/useLedgerChain'
import { useAnalysisSession } from '@/services/analysisSessionContext'

const HEADER = (
  <header className="wx-header">
    <div>
      <span className="wx-mono wx-kicker">Investigation / 08 · integrity</span>
      <h1>Audit Ledger</h1>
      <p>
        Every forecast is hash-chained and Merkle-anchored. This console rebuilds the chain from the
        analysed capture with real browser cryptography, then lets you break it two ways and watch
        verification catch each one.
      </p>
    </div>
  </header>
)

export default function LedgerPage() {
  const { session } = useAnalysisSession()
  const forecasts = useMemo(() => session?.result.forecasts ?? [], [session])

  const { state, tamperEdit, tamperRewrite, restore } = useLedgerChain(forecasts)
  const [selectedIndex, setSelectedIndex] = useState(0)

  if (!session) {
    return (
      <div>
        {HEADER}
        <div style={{ marginTop: 18 }}>
          <DashboardEmptyState />
        </div>
      </div>
    )
  }

  const busy = state.phase === 'computing'

  return (
    <div>
      {HEADER}

      {session.isFixture && (
        <div className="wx-notice tone-warn" role="note" style={{ marginTop: 16 }}>
          <FlaskConical size={15} aria-hidden="true" />
          <div>
            <span className="wx-pill wx-mono tone-warn" style={{ marginRight: 8 }}>
              <i aria-hidden="true" /> demo fixture — not engine output
            </span>
            Records were built from the fixture forecasts. The hash construction, pseudonyms, Merkle
            root and verification below are all real cryptography.
          </div>
        </div>
      )}

      {state.phase === 'error' && (
        <div className="wx-notice tone-danger" role="alert" style={{ marginTop: 16 }}>
          <AlertTriangle size={15} aria-hidden="true" />
          <div>{state.error}</div>
        </div>
      )}

      {state.phase === 'computing' && state.entries.length === 0 && (
        <div className="wx-notice" role="status" style={{ marginTop: 16 }}>
          <Loader2 size={15} className="wx-spin" aria-hidden="true" />
          <div>Computing chain… hashing {forecasts.length} records with SHA-256 / HMAC.</div>
        </div>
      )}

      {state.phase !== 'error' && state.entries.length > 0 && (
        <>
          <LedgerMetrics state={state} />

          <div style={{ marginTop: 14 }}>
            <LedgerChainView
              entries={state.entries}
              firstBadIndex={state.verifyResult?.firstBadIndex ?? null}
              selectedIndex={selectedIndex}
              onSelect={setSelectedIndex}
            />
          </div>

          <div className="wx-columns">
            <LedgerTamperPanel
              state={state}
              selectedIndex={selectedIndex}
              onSelectIndex={setSelectedIndex}
              onEdit={tamperEdit}
              onRewrite={tamperRewrite}
              onRestore={restore}
              busy={busy}
            />
            <div className="wx-stack">
              <LedgerProvenancePanel />
              <LedgerVerifyGuide />
            </div>
          </div>
        </>
      )}

      {state.phase !== 'error' && state.phase === 'ready' && state.entries.length === 0 && (
        <div className="wx-notice" role="status" style={{ marginTop: 16 }}>
          <AlertTriangle size={15} aria-hidden="true" />
          <div>
            This capture produced no forecasts, so the ledger has no records to chain. An empty
            chain hashes to the empty-leaf Merkle root, matching the Python verifier.
          </div>
        </div>
      )}
    </div>
  )
}
