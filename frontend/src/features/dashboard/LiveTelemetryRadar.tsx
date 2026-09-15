import { Activity, Cpu, Network, Radio, Shield, Waves } from 'lucide-react'

import { formatPercent } from '@/lib/format'
import type { ActiveRunInfo } from '@/services/analysisSessionContext'

interface LiveTelemetryRadarProps {
  activeRun: ActiveRunInfo
  onCancel?: () => void
}

export function LiveTelemetryRadar({ activeRun, onCancel }: LiveTelemetryRadarProps) {
  return (
    <div style={{ maxWidth: 840, margin: '24px auto', padding: '0 16px' }}>
      <header className="wx-header" style={{ marginBottom: 24 }}>
        <div>
          <span className="wx-mono wx-kicker">Operations / 01 · telemetry stream</span>
          <h1>Live Telemetry Ingestion & Feature Extraction</h1>
          <p>
            Processing live network capture: slicing temporal windows, constructing host interaction
            graphs, and preparing predictive RSSM world model rollout.
          </p>
        </div>
      </header>

      <div
        className="wx-panel"
        style={{
          border: '1px solid var(--c-line)',
          borderRadius: 16,
          padding: '28px 24px',
          background: 'var(--c-panel)',
          boxShadow: 'var(--shadow-md)',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Animated Scanner Bar at Top */}
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: 3,
            background: 'linear-gradient(90deg, var(--c-accent), #38bdf8, var(--c-accent))',
            backgroundSize: '200% 100%',
            animation: 'wx-gradient-pan 1.8s ease infinite',
          }}
        />

        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 20 }}>
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: '50%',
              background: 'rgba(37, 99, 235, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--c-accent)',
            }}
          >
            <Radio size={22} className="wx-spin" style={{ animationDuration: '3s' }} />
          </div>
          <div>
            <div className="wx-mono" style={{ fontSize: 11, color: 'var(--c-text-muted)' }}>
              TARGET CAPTURE INGESTION
            </div>
            <div style={{ fontSize: 18, fontWeight: 780 }}>{activeRun.inputName}</div>
          </div>
        </div>

        {/* Live Status Pill */}
        <div
          style={{
            padding: '12px 16px',
            borderRadius: 10,
            background: 'var(--c-bg)',
            border: '1px solid var(--c-line)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
            marginBottom: 24,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: '50%',
                background: 'var(--c-accent)',
                boxShadow: '0 0 10px var(--c-accent)',
              }}
            />
            <span className="wx-mono" style={{ fontSize: 13, fontWeight: 600 }}>
              {activeRun.stage ?? 'Extracting temporal graph features...'}
            </span>
          </div>
          <span className="wx-pill wx-mono" style={{ fontSize: 10, color: 'var(--c-accent)' }}>
            FPR Budget: {formatPercent(activeRun.fprBudget, 1)}
          </span>
        </div>

        {/* Pipeline Ingestion Steps Grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: 12,
            marginBottom: 24,
          }}
        >
          <div
            style={{
              padding: '12px',
              borderRadius: 10,
              background: 'var(--c-bg)',
              border: '1px solid var(--c-line)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--c-text-muted)', fontSize: 11 }} className="wx-mono">
              <Network size={13} style={{ color: 'var(--c-accent)' }} />
              <span>WINDOW SLICING</span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 700, margin: '6px 0 2px' }}>15s Windows</div>
            <div style={{ fontSize: 11, color: 'var(--c-text-muted)' }}>5s step stride rate</div>
          </div>

          <div
            style={{
              padding: '12px',
              borderRadius: 10,
              background: 'var(--c-bg)',
              border: '1px solid var(--c-line)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--c-text-muted)', fontSize: 11 }} className="wx-mono">
              <Cpu size={13} style={{ color: '#7c3aed' }} />
              <span>GRAPH TOPOLOGY</span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 700, margin: '6px 0 2px' }}>Bipartite Hosts</div>
            <div style={{ fontSize: 11, color: 'var(--c-text-muted)' }}>Fanout & degree stats</div>
          </div>

          <div
            style={{
              padding: '12px',
              borderRadius: 10,
              background: 'var(--c-bg)',
              border: '1px solid var(--c-line)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--c-text-muted)', fontSize: 11 }} className="wx-mono">
              <Activity size={13} style={{ color: 'var(--c-success)' }} />
              <span>WORLD MODEL RSSM</span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 700, margin: '6px 0 2px' }}>k=12 Rollout</div>
            <div style={{ fontSize: 11, color: 'var(--c-text-muted)' }}>+60s lookahead forecast</div>
          </div>

          <div
            style={{
              padding: '12px',
              borderRadius: 10,
              background: 'var(--c-bg)',
              border: '1px solid var(--c-line)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--c-text-muted)', fontSize: 11 }} className="wx-mono">
              <Shield size={13} style={{ color: '#d97706' }} />
              <span>DECISION BOUNDARY</span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 700, margin: '6px 0 2px' }}>1.0% FPR Cutoff</div>
            <div style={{ fontSize: 11, color: 'var(--c-text-muted)' }}>Strict alert calibration</div>
          </div>
        </div>

        {/* Action Controls */}
        {onCancel && (
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button type="button" className="wx-btn wx-mono" onClick={onCancel} style={{ fontSize: 12 }}>
              Cancel Ingestion
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
