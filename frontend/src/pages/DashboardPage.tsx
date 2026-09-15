import { useCallback, useMemo, useRef, useState } from 'react'
import { useSearchParams } from 'react-router'
import { CheckCircle2, Radio } from 'lucide-react'

import { AttackImpactBanner } from '@/features/dashboard/AttackImpactBanner'
import { AttackProgression } from '@/features/dashboard/AttackProgression'
import { CaptureContextBar } from '@/features/dashboard/CaptureContextBar'
import { CriticalHostCard } from '@/features/dashboard/CriticalHostCard'
import { DashboardEmptyState } from '@/features/dashboard/DashboardEmptyState'
import { EvidenceRail } from '@/features/dashboard/EvidenceRail'
import { HostTriageTable } from '@/features/dashboard/HostTriageTable'
import { KpiRow } from '@/features/dashboard/KpiRow'
import { LiveTelemetryRadar } from '@/features/dashboard/LiveTelemetryRadar'
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
import { formatSeconds } from '@/lib/format'
import { useAnalysisSession } from '@/services/analysisSessionContext'

export default function DashboardPage() {
  const { session, activeRun, cancelActiveRun } = useAnalysisSession()
  const [searchParams, setSearchParams] = useSearchParams()
  const isLiveStreamParam = searchParams.get('stream') === 'live'

  const [streamProgress, setStreamProgress] = useState<{
    index: number
    total: number
    isPlaying: boolean
  } | null>(null)

  const lastKpiUpdateRef = useRef<number>(0)

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

  const handleStreamChange = useCallback(
    (index: number, total: number, isPlaying: boolean) => {
      const now = performance.now()
      // Always update on stream completion, when playback stops, or after at least 500ms
      if (index >= total || !isPlaying || now - lastKpiUpdateRef.current >= 500) {
        lastKpiUpdateRef.current = now
        setStreamProgress({ index, total, isPlaying })
      }
    },
    [],
  )

  const totalWindows = derived?.timeline.length ?? 0
  const isStreaming = Boolean(
    isLiveStreamParam &&
      streamProgress &&
      streamProgress.index < streamProgress.total &&
      streamProgress.isPlaying,
  )
  const currentStreamIndex = streamProgress?.index ?? totalWindows

  const visiblePoints = useMemo(() => {
    if (!derived) return []
    return derived.timeline.slice(0, currentStreamIndex)
  }, [derived, currentStreamIndex])

  const visibleAlerts = useMemo(() => {
    if (!result) return 0
    return visiblePoints.filter((p) => p.networkScore >= result.threshold).length
  }, [visiblePoints, result])

  const visiblePeak = useMemo(() => {
    if (visiblePoints.length === 0) return null
    return Math.max(...visiblePoints.map((p) => p.networkScore))
  }, [visiblePoints])

  // 1. If actively ingesting telemetry and no session yet, show live radar screen
  if (!session || !result || !derived) {
    if (activeRun?.isRunning) {
      return <LiveTelemetryRadar activeRun={activeRun} onCancel={cancelActiveRun} />
    }

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

      {/* Streaming Status Banner */}
      {isStreaming && (
        <div
          style={{
            marginTop: 16,
            padding: '10px 16px',
            borderRadius: 10,
            background: 'rgba(37, 99, 235, 0.08)',
            border: '1px solid rgba(37, 99, 235, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Radio size={16} className="wx-spin" style={{ color: 'var(--c-accent)' }} />
            <span className="wx-mono" style={{ fontSize: 13, fontWeight: 600 }}>
              ⚡ Live Telemetry Stream In Progress — Processing Window {currentStreamIndex} of{' '}
              {totalWindows} ({totalWindows > 0 ? Math.round((currentStreamIndex / totalWindows) * 100) : 0}%)
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="wx-mono" style={{ fontSize: 11, color: 'var(--c-text-muted)' }}>
              Active Cursor: {visiblePoints[visiblePoints.length - 1]?.host ?? '—'}
            </span>
            <button
              type="button"
              className="wx-btn wx-mono"
              style={{ padding: '2px 8px', fontSize: 11 }}
              onClick={() => setSearchParams({}, { replace: true })}
            >
              Show All
            </button>
          </div>
        </div>
      )}

      {/* Stream Completed Notification Banner */}
      {!isStreaming && isLiveStreamParam && streamProgress && streamProgress.index >= streamProgress.total && (
        <div
          style={{
            marginTop: 16,
            padding: '10px 16px',
            borderRadius: 10,
            background: 'rgba(5, 150, 105, 0.08)',
            border: '1px solid rgba(5, 150, 105, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <CheckCircle2 size={16} style={{ color: 'var(--c-success)' }} />
            <span className="wx-mono" style={{ fontSize: 13, fontWeight: 600, color: 'var(--c-success)' }}>
              ✅ Threat Trajectory Forecast Complete — Primary Host {critical?.host} Isolated with{' '}
              {derived.lead.seconds !== null ? formatSeconds(derived.lead.seconds) : 'Early'} Lead Time
            </span>
          </div>
          <button
            type="button"
            className="wx-btn wx-mono"
            style={{ padding: '2px 8px', fontSize: 11 }}
            onClick={() => setSearchParams({}, { replace: true })}
          >
            Dismiss
          </button>
        </div>
      )}

      <div style={{ marginTop: 16 }}>
        <CaptureContextBar session={session} />
      </div>

      <AttackImpactBanner
        criticalHost={critical}
        lead={derived.lead}
        result={result}
        isStreaming={isStreaming}
      />

      <KpiRow
        result={result}
        peak={derived.peak}
        lead={derived.lead}
        isStreaming={isStreaming}
        streamIndex={currentStreamIndex}
        totalWindows={totalWindows}
        visibleAlerts={visibleAlerts}
        visiblePeak={visiblePeak}
      />

      <div className="dash-row is-primary">
        <ThreatActivityChart
          points={derived.timeline}
          threshold={result.threshold}
          autoStream={isLiveStreamParam}
          onStreamChange={handleStreamChange}
        />
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
