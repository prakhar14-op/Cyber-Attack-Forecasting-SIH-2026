import { ArrowLeft, Info } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router'

import { DashboardEmptyState } from '@/features/dashboard/DashboardEmptyState'
import { hostRanking } from '@/features/dashboard/dashboardSelectors'
import { ContributingWindows } from '@/features/incident/ContributingWindows'
import { FeatureContributions } from '@/features/incident/FeatureContributions'
import { FlaggedFlows } from '@/features/incident/FlaggedFlows'
import { IncidentActions } from '@/features/incident/IncidentActions'
import { IncidentHeader } from '@/features/incident/IncidentHeader'
import { formatPercent, formatWindowStart } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'
import { useAnalysisSession } from '@/services/analysisSessionContext'
import { useReplay } from '@/services/replayContext'

export default function IncidentPage() {
  const { host: hostParam } = useParams()
  const host = hostParam ? decodeURIComponent(hostParam) : ''
  const { session } = useAnalysisSession()
  const replay = useReplay()

  const result = session?.result ?? null
  const rows = useMemo(() => (result ? hostRanking(result) : []), [result])
  const row = rows.find((entry) => entry.host === host) ?? null

  // Alerts on this host, newest first; the analyst can walk them.
  const alerts = useMemo(
    () =>
      (result?.forecasts ?? [])
        .filter((forecast) => forecast.host === host)
        .sort((a, b) => b.probability - a.probability),
    [host, result],
  )
  const [selectedWindow, setSelectedWindow] = useState<number | null>(null)
  const forecast = alerts.find((entry) => entry.window_start === selectedWindow) ?? alerts[0] ?? null

  const internal = useMemo(
    () => result?.graph.nodes.find((node) => node.ip === host)?.internal ?? null,
    [host, result],
  )

  const seekToFirstAlert = useCallback(() => {
    if (alerts.length === 0) return
    replay.setCursor(Math.min(...alerts.map((entry) => entry.window_start)))
  }, [alerts, replay])

  const header = (
    <header className="wx-header">
      <div>
        <span className="wx-mono wx-kicker">Investigation / 05 · evidence</span>
        <h1>Incident workspace</h1>
        <p>
          Everything the engine recorded about one source host: the named features that moved the
          score, the windows where the evidence formed, and the flows inside the alert window.
        </p>
      </div>
      <div className="wx-header-status">
        <Link className="wx-btn" to="/dashboard">
          <ArrowLeft size={14} aria-hidden="true" /> Back to triage
        </Link>
      </div>
    </header>
  )

  if (!session || !result) {
    return (
      <div>
        {header}
        <div style={{ marginTop: 18 }}>
          <DashboardEmptyState />
        </div>
      </div>
    )
  }

  if (!row || !forecast) {
    return (
      <div>
        {header}
        <div className="wx-panel" style={{ marginTop: 18 }}>
          <div className="wx-panel-head">
            <span className="wx-mono">{host ? `No alert for ${host}` : 'Select a host to investigate'}</span>
            <span className="wx-mono">{rows.length} alerting hosts in this capture</span>
          </div>
          <div className="wx-panel-body" style={{ display: 'grid', gap: 8 }}>
            <p className="wx-stage-note" style={{ margin: 0 }}>
              {host
                ? `The analysed capture has no forecast rows for ${host}, so there is no evidence to show. Pick a host that did alert:`
                : 'The incident workspace describes one source host. Pick one of the hosts that alerted in this capture:'}
            </p>
            {rows.length === 0 ? (
              <p className="wx-stage-note" style={{ margin: 0 }}>
                No host alerted in this capture.
              </p>
            ) : (
              rows.map((entry, index) => (
                <Link
                  key={entry.host}
                  className="wx-row"
                  to={`/incident/${encodeURIComponent(entry.host)}`}
                  style={{ textDecoration: 'none' }}
                >
                  <span className="wx-row-icon wx-mono" aria-hidden="true">
                    {String(index + 1).padStart(2, '0')}
                  </span>
                  <span>
                    <strong className="dash-host">{entry.host}</strong>
                    <small>
                      {entry.alerts} alerts · peak {formatPercent(entry.peakProbability, 1)} ·{' '}
                      {stageLabel(entry.dominantStage)}
                    </small>
                  </span>
                  <span className="stage-badge" style={{ color: stageColor(entry.dominantStage) }}>
                    <i aria-hidden="true" /> {stageLabel(entry.dominantStage)}
                  </span>
                </Link>
              ))
            )}
          </div>
        </div>
      </div>
    )
  }

  return (
    <div>
      {header}

      <div style={{ marginTop: 16, display: 'grid', gap: 12 }}>
        <IncidentHeader
          host={host}
          row={row}
          forecast={forecast}
          threshold={result.threshold}
          internal={internal}
        />

        {alerts.length > 1 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 7 }}>
            <span className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
              alert window
            </span>
            {alerts.slice(0, 12).map((entry) => {
              const active = entry.window_start === forecast.window_start
              return (
                <button
                  key={entry.window_start}
                  type="button"
                  className={`wx-btn wx-mono${active ? ' is-primary' : ''}`}
                  style={{ minHeight: 30 }}
                  aria-pressed={active}
                  onClick={() => setSelectedWindow(entry.window_start)}
                >
                  <span style={{ color: active ? '#fff' : stageColor(entry.stage) }}>●</span>
                  {formatWindowStart(entry.window_start)} · {formatPercent(entry.probability, 0)}
                </button>
              )
            })}
            {alerts.length > 12 && (
              <span className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
                +{alerts.length - 12} more
              </span>
            )}
          </div>
        )}

        <div className="dash-row is-triage" style={{ marginTop: 0 }}>
          <FeatureContributions features={forecast.top_features} />
          <ContributingWindows
            windows={forecast.top_windows}
            alertWindow={forecast.window_start}
            threshold={result.threshold}
          />
        </div>

        <FlaggedFlows flows={forecast.flagged_flows} />

        <IncidentActions
          host={host}
          result={result}
          onReplayFromFirstAlert={seekToFirstAlert}
        />

        <div className="wx-notice" role="note">
          <Info size={15} aria-hidden="true" />
          <div>
            Selected window {formatWindowStart(forecast.window_start)} ·{' '}
            <span style={{ color: stageColor(forecast.stage) }}>{stageLabel(forecast.stage)}</span> ·{' '}
            {forecast.technique ? `${forecast.technique} ${forecast.technique_name}` : 'no technique mapped'}.
            Contributions are TreeSHAP values on the engine's named window features; nothing on this
            page is derived from any other host.
          </div>
        </div>
      </div>
    </div>
  )
}
