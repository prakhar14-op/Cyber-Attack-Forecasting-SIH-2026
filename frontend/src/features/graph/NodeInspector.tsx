import { ArrowRight, Info, ShieldMinus, X } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'

import type { GraphNode3D } from '@/features/graph/graphModel'
import { hostEvidence } from '@/features/graph/graphModel'
import { formatInt, formatPercent, formatWindowStart } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'
import { analysisEngine } from '@/services/analysisEngine'
import type { ContainmentOutcome } from '@/services/analysisEngine'
import type { PredictionResult } from '@/types/backend'

interface NodeInspectorProps {
  node: GraphNode3D
  result: PredictionResult
  onClose: () => void
}

const ZONE_LABEL: Record<GraphNode3D['zone'], string> = {
  internal: 'internal',
  external: 'external',
  unknown: 'not derived',
}

export function NodeInspector({ node, result, onClose }: NodeInspectorProps) {
  const evidence = hostEvidence(result, node.ip)
  const [outcome, setOutcome] = useState<ContainmentOutcome | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // A containment result belongs to one host; drop it when the selection moves.
  useEffect(() => {
    setOutcome(null)
    setError(null)
    setPending(false)
  }, [node.ip])

  const contain = useCallback(async () => {
    setPending(true)
    setError(null)
    try {
      setOutcome(await analysisEngine.containHost(result, node.ip))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'containment failed')
    } finally {
      setPending(false)
    }
  }, [node.ip, result])

  return (
    <aside className="graph-inspector" aria-label={`Host ${node.ip}`}>
      <div className="wx-panel-head">
        <span className="wx-mono">Host inspector</span>
        <button
          type="button"
          className="wx-btn"
          style={{ minHeight: 26, padding: '0 8px' }}
          onClick={onClose}
          aria-label="Close host inspector"
        >
          <X size={13} aria-hidden="true" />
        </button>
      </div>

      <div className="wx-panel-body" style={{ display: 'grid', gap: 13 }}>
        <div>
          <div className="dash-host" style={{ fontSize: 15 }}>
            {node.ip}
          </div>
          <div
            className="dash-critical-value"
            style={{ fontSize: '2.1rem', color: node.alerts > 0 ? 'var(--c-danger)' : 'var(--c-text-muted)' }}
          >
            {node.alerts > 0 ? formatPercent(node.peakProb, 1) : 'no alert'}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7, marginTop: 10 }}>
            <span className="wx-pill wx-mono">{ZONE_LABEL[node.zone]}</span>
            <span className="wx-pill wx-mono">{formatInt(node.alerts)} alerts</span>
            {evidence.dominantStage && (
              <span className="stage-badge" style={{ color: stageColor(evidence.dominantStage) }}>
                <i aria-hidden="true" /> {stageLabel(evidence.dominantStage)}
              </span>
            )}
          </div>
        </div>

        <dl style={{ margin: 0 }}>
          <div className="wx-kv wx-mono">
            <dt>Peak probability</dt>
            <dd>{node.alerts > 0 ? formatPercent(node.peakProb, 2) : '—'}</dd>
          </div>
          <div className="wx-kv wx-mono">
            <dt>Flow weight</dt>
            <dd>{formatInt(node.degree)}</dd>
          </div>
          {evidence.peakForecast && (
            <div className="wx-kv wx-mono">
              <dt>Peak window</dt>
              <dd>{formatWindowStart(evidence.peakForecast.window_start)}</dd>
            </div>
          )}
          {evidence.firstWindow !== null && evidence.lastWindow !== null && (
            <div className="wx-kv wx-mono">
              <dt>Alert span</dt>
              <dd>
                {formatWindowStart(evidence.firstWindow)} → {formatWindowStart(evidence.lastWindow)}
              </dd>
            </div>
          )}
          {evidence.technique && (
            <div className="wx-kv wx-mono">
              <dt>Technique</dt>
              <dd>
                {evidence.technique}
                {evidence.techniqueName ? ` · ${evidence.techniqueName}` : ''}
              </dd>
            </div>
          )}
          {evidence.stages.length > 1 && (
            <div className="wx-kv wx-mono">
              <dt>Stages seen</dt>
              <dd>{evidence.stages.map((stage) => stageLabel(stage)).join(', ')}</dd>
            </div>
          )}
        </dl>

        {evidence.peakForecast && evidence.peakForecast.top_features.length > 0 && (
          <div>
            <div className="wx-mono" style={{ marginBottom: 7, color: 'var(--c-text-muted)' }}>
              Named-feature evidence
            </div>
            <ul className="dash-evidence">
              {evidence.peakForecast.top_features.slice(0, 4).map((feature) => (
                <li key={feature.feature}>
                  <span>{feature.feature}</span>
                  <span className="dash-contrib">
                    {feature.contribution > 0 ? '+' : ''}
                    {feature.contribution}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <div style={{ display: 'grid', gap: 8 }}>
          <button
            type="button"
            className="wx-btn"
            onClick={contain}
            disabled={pending || node.alerts === 0}
          >
            <ShieldMinus size={14} aria-hidden="true" />
            {pending ? 'Running ablation…' : 'Contain host (what-if)'}
          </button>

          {node.alerts === 0 && (
            <p className="wx-stage-note" style={{ margin: 0 }}>
              This host raised no alert, so containing it removes nothing to measure.
            </p>
          )}

          {error && (
            <div className="wx-notice tone-danger" role="alert">
              <Info size={14} aria-hidden="true" />
              <div>{error}</div>
            </div>
          )}

          {outcome && (
            <div style={{ border: '1px solid var(--c-line)', borderRadius: 11, padding: 12 }}>
              <div className="wx-mono" style={{ color: 'var(--c-text-muted)', marginBottom: 8 }}>
                Containment · {outcome.basis === 'engine' ? 'engine re-run' : 'own alert rows'}
              </div>
              <dl style={{ margin: 0 }}>
                <div className="wx-kv wx-mono">
                  <dt>Before · alerts</dt>
                  <dd>{formatInt(outcome.beforeAlerts)}</dd>
                </div>
                <div className="wx-kv wx-mono">
                  <dt>After containment</dt>
                  <dd>{formatInt(outcome.afterAlerts)}</dd>
                </div>
                <div className="wx-kv wx-mono">
                  <dt>Delta</dt>
                  <dd style={{ color: outcome.deltaAlerts < 0 ? 'var(--c-success)' : 'var(--c-text)' }}>
                    {outcome.deltaAlerts}
                  </dd>
                </div>
                <div className="wx-kv wx-mono">
                  <dt>Peak before → after</dt>
                  <dd>
                    {outcome.beforePeak === null ? '—' : formatPercent(outcome.beforePeak, 1)} →{' '}
                    {outcome.afterPeak === null ? 'none' : formatPercent(outcome.afterPeak, 1)}
                  </dd>
                </div>
              </dl>
              <p className="wx-stage-note" style={{ marginTop: 9 }}>
                {outcome.note}
              </p>
            </div>
          )}

          <Link className="wx-btn is-primary" to={`/incident/${encodeURIComponent(node.ip)}`}>
            Open incident <ArrowRight size={14} aria-hidden="true" />
          </Link>
        </div>
      </div>
    </aside>
  )
}
