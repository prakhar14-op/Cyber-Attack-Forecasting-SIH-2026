import { useMemo } from 'react'

import { AttackProgression } from '@/features/dashboard/AttackProgression'
import { CaptureContextBar } from '@/features/dashboard/CaptureContextBar'
import { CriticalHostCard } from '@/features/dashboard/CriticalHostCard'
import { DashboardEmptyState } from '@/features/dashboard/DashboardEmptyState'
import { EvidenceRail } from '@/features/dashboard/EvidenceRail'
import { HostTriageTable } from '@/features/dashboard/HostTriageTable'
import { KpiRow } from '@/features/dashboard/KpiRow'
import { NetworkPreview } from '@/features/dashboard/NetworkPreview'
import { StageDistribution } from '@/features/dashboard/StageDistribution'
import { ThreatActivityChart } from '@/features/dashboard/ThreatActivityChart'
import {
  attackProgression,
  hostRanking,
  leadEvidence,
  networkPreview,
  peakProbability,
  stageDistribution,
  threatTimeline,
} from '@/features/dashboard/dashboardSelectors'
import { useAnalysisSession } from '@/services/analysisSessionContext'

export default function DashboardPage() {
  const { session } = useAnalysisSession()
  const result = session?.result ?? null

  const derived = useMemo(() => {
    if (!result) return null
    return {
      peak: peakProbability(result),
      lead: leadEvidence(result),
      hosts: hostRanking(result),
      timeline: threatTimeline(result),
      stages: stageDistribution(result),
      progression: attackProgression(result),
      preview: networkPreview(result),
    }
  }, [result])

  if (!session || !result || !derived) {
    return (
      <div>
        <header className="wx-header">
          <div>
            <span className="wx-mono wx-kicker">Operations / 02 · triage</span>
            <h1>SOC Dashboard</h1>
            <p>
              Network-level threat state for the analysed capture: what fired, which source host to
              open first, and how the attack progressed.
            </p>
          </div>
        </header>
        <div style={{ marginTop: 18 }}>
          <DashboardEmptyState />
        </div>
      </div>
    )
  }

  const critical = derived.hosts[0]

  return (
    <div>
      <header className="wx-header">
        <div>
          <span className="wx-mono wx-kicker">Operations / 02 · triage</span>
          <h1>SOC Dashboard</h1>
          <p>
            Network-level threat state for the analysed capture: what fired, which source host to
            open first, and how the attack progressed.
          </p>
        </div>
      </header>

      <div style={{ marginTop: 16 }}>
        <CaptureContextBar session={session} />
      </div>

      <KpiRow result={result} peak={derived.peak} lead={derived.lead} />

      <div className="dash-row is-primary">
        <ThreatActivityChart points={derived.timeline} threshold={result.threshold} />
        <StageDistribution stages={derived.stages} />
      </div>

      <div className="dash-row is-triage">
        <div className="wx-stack">
          <HostTriageTable rows={derived.hosts} />
          <AttackProgression steps={derived.progression} />
        </div>
        {critical && <CriticalHostCard row={critical} />}
      </div>

      <div className="dash-row">
        <NetworkPreview preview={derived.preview} />
      </div>

      <div className="dash-row">
        <EvidenceRail />
      </div>
    </div>
  )
}
