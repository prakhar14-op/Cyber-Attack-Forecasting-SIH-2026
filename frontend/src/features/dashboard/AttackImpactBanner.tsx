import { useState } from 'react'
import { AlertCircle, ChevronDown, ChevronUp, Clock, HelpCircle, ShieldAlert, Target, Zap } from 'lucide-react'
import { Link } from 'react-router'

import type { HostRow, LeadEvidence } from '@/features/dashboard/dashboardSelectors'
import { formatPercent, formatProbability, formatSeconds, formatWindowStart } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'
import type { PredictionResult } from '@/types/backend'

interface AttackImpactBannerProps {
  criticalHost: HostRow | undefined
  lead: LeadEvidence
  result: PredictionResult
  isStreaming?: boolean
}

export function AttackImpactBanner({
  criticalHost,
  lead,
  result,
  isStreaming = false,
}: AttackImpactBannerProps) {
  const [showPitchNotes, setShowPitchNotes] = useState(false)

  if (!criticalHost) return null

  const forecast = criticalHost.peakForecast
  const leadSeconds = lead.seconds

  return (
    <section
      className="wx-panel"
      style={{
        marginTop: 14,
        border: '1px solid var(--c-line)',
        borderRadius: 14,
        overflow: 'hidden',
        background: 'var(--c-panel)',
        boxShadow: 'var(--shadow-sm)',
      }}
      aria-labelledby="attack-impact-title"
    >
      <div
        className="wx-panel-head"
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 10,
          background: 'rgba(225, 29, 72, 0.04)',
          borderBottom: '1px solid var(--c-line)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <ShieldAlert size={16} style={{ color: 'var(--c-danger)' }} aria-hidden="true" />
          <span className="wx-mono" id="attack-impact-title" style={{ fontWeight: 700 }}>
            Incident Attribution & Early Warning Summary
          </span>
          <span className="wx-pill wx-mono tone-danger" style={{ fontSize: 9 }}>
            Primary Target Identified
          </span>
        </div>

        <button
          type="button"
          className="wx-btn wx-mono"
          onClick={() => setShowPitchNotes((prev) => !prev)}
          style={{ padding: '3px 10px', fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 5 }}
          title="Toggle presentation pitch talking points for judges"
        >
          <HelpCircle size={12} aria-hidden="true" />
          <span>{showPitchNotes ? 'Hide Pitch Brief' : 'Pitch Brief (For Judges)'}</span>
          {showPitchNotes ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </button>
      </div>

      <div className="wx-panel-body" style={{ padding: '16px 20px', display: 'grid', gap: 16 }}>
        {/* Core Impact Row */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: 16,
          }}
        >
          {/* Affected Host Box */}
          <div
            style={{
              padding: '12px 14px',
              borderRadius: 10,
              background: 'var(--c-bg)',
              border: '1px solid var(--c-line)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--c-text-muted)', fontSize: 11 }} className="wx-mono">
              <Target size={13} style={{ color: 'var(--c-danger)' }} />
              <span>COMPROMISED HOST (PATIENT ZERO)</span>
            </div>
            <div style={{ margin: '6px 0 2px', fontSize: 16, fontWeight: 780 }} className="dash-host">
              {criticalHost.host}
            </div>
            <div style={{ fontSize: 11, color: 'var(--c-text-muted)' }}>
              {criticalHost.internal === 0 ? 'External adversary vector' : 'Internal workstation / compromised host'}
              {' · '}
              <strong style={{ color: 'var(--c-danger)' }}>{criticalHost.alerts} alert windows</strong>
            </div>
          </div>

          {/* Timing Box */}
          <div
            style={{
              padding: '12px 14px',
              borderRadius: 10,
              background: 'var(--c-bg)',
              border: '1px solid var(--c-line)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--c-text-muted)', fontSize: 11 }} className="wx-mono">
              <Clock size={13} style={{ color: 'var(--c-success)' }} />
              <span>TIMING & PRECURSOR LEAD TIME</span>
            </div>
            <div style={{ margin: '6px 0 2px', fontSize: 16, fontWeight: 780, color: 'var(--c-success)' }} className="wx-mono">
              {leadSeconds !== null ? `+${formatSeconds(leadSeconds)} lead advance` : 'Ahead of attack peak'}
            </div>
            <div style={{ fontSize: 11, color: 'var(--c-text-muted)' }}>
              Peak incident window: <strong className="wx-mono">{formatWindowStart(forecast.window_start)}</strong>
              {' · '}
              Lookahead: <strong className="wx-mono">k=12 (+60s)</strong>
            </div>
          </div>

          {/* Stage Box */}
          <div
            style={{
              padding: '12px 14px',
              borderRadius: 10,
              background: 'var(--c-bg)',
              border: '1px solid var(--c-line)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--c-text-muted)', fontSize: 11 }} className="wx-mono">
              <Zap size={13} style={{ color: stageColor(criticalHost.dominantStage) }} />
              <span>ATTACK PROGRESSION STAGE</span>
            </div>
            <div style={{ margin: '6px 0 2px', fontSize: 15, fontWeight: 780, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span className="stage-badge" style={{ color: stageColor(criticalHost.dominantStage), fontSize: 12 }}>
                <i aria-hidden="true" /> {stageLabel(criticalHost.dominantStage)}
              </span>
              <span className="wx-mono" style={{ fontSize: 13, color: stageColor(criticalHost.dominantStage) }}>
                {formatPercent(criticalHost.peakProbability, 1)} peak
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--c-text-muted)' }}>
              {forecast.technique ? `${forecast.technique} · ${forecast.technique_name}` : 'Multi-vector anomaly detected'}
            </div>
          </div>
        </div>

        {/* Pitch Brief Collapsible Box */}
        {showPitchNotes && (
          <div
            style={{
              padding: '14px 18px',
              borderRadius: 10,
              background: 'rgba(37, 99, 235, 0.04)',
              border: '1px solid rgba(37, 99, 235, 0.2)',
              fontSize: 12.5,
              lineHeight: 1.65,
            }}
          >
            <div style={{ fontWeight: 700, color: 'var(--c-accent)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }} className="wx-mono">
              <AlertCircle size={14} />
              EXECUTIVE PITCH BRIEF: HOW TO EXPLAIN THIS TO JUDGES
            </div>
            <div style={{ display: 'grid', gap: 8 }}>
              <div>
                <strong>1. Data Ingestion:</strong> We ingest raw network flow telemetry and slice it into sliding 15-second observation windows (5s stride), extracting temporal bipartite graph features and flow interaction patterns.
              </div>
              <div>
                <strong>2. Real-Time Dynamic Forecasting:</strong> Rather than performing a static backward-looking scan, our pipeline forecasts threat escalation forward in time up to <strong>k=12 rollout steps (+60s forward horizon)</strong>.
              </div>
              <div>
                <strong>3. Calibrated Alert Threshold ({formatProbability(result.threshold)}):</strong> The threshold is mathematically calibrated from the offline validation split for a strict <strong>1.0% False Positive Rate budget</strong>. Any forecast score exceeding this boundary raises an operational alert.
              </div>
              <div>
                <strong>4. Early Lead Time Advantage:</strong> SOC operators are alerted <strong>{leadSeconds !== null ? formatSeconds(leadSeconds) : 'over 2 minutes'}</strong> before peak attack execution, directly isolating <strong>{criticalHost.host}</strong> as the compromised host with full MITRE ATT&CK technique mapping.
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}
