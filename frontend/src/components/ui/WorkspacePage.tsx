import { Check, CircleDashed, DatabaseZap } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import { Panel } from '@/components/ui/Panel'
import { StatusBadge } from '@/components/ui/StatusBadge'

interface WorkspacePageProps {
  eyebrow: string
  title: string
  description: string
  icon: LucideIcon
  plannedViews: readonly string[]
}

const foundationState = [
  { label: 'Route and shell', state: 'Ready', ready: true },
  { label: 'Real SIH data', state: 'Not connected', ready: false },
  { label: 'Interactive view', state: 'Next phase', ready: false },
] as const

export function WorkspacePage({ eyebrow, title, description, icon: Icon, plannedViews }: WorkspacePageProps) {
  return (
    <div>
      <header className="workspace-header">
        <div>
          <div className="mono-label" style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--accent)' }}>
            <Icon size={14} strokeWidth={1.8} /> {eyebrow}
          </div>
          <h1 className="workspace-title">{title}</h1>
          <p className="workspace-description">{description}</p>
        </div>
        <StatusBadge tone="accent">Foundation route</StatusBadge>
      </header>

      <div className="foundation-grid">
        <Panel className="foundation-card">
          <div className="mono-label" style={{ color: 'var(--text-muted)' }}>Planned workspace</div>
          <div className="preview-grid">
            {plannedViews.map((view, index) => (
              <div className="preview-cell" key={view}>
                <div className="mono-label" style={{ color: index === 0 ? 'var(--accent)' : 'var(--text-muted)', fontSize: 8 }}>
                  Module {String(index + 1).padStart(2, '0')}
                </div>
                <div className="preview-value" style={{ fontSize: 14 }}>{view}</div>
                <div style={{ color: 'var(--text-muted)', fontSize: 11 }}>Awaiting real pipeline output</div>
              </div>
            ))}
          </div>
          <div
            style={{
              position: 'absolute',
              right: 20,
              bottom: 18,
              display: 'flex',
              alignItems: 'center',
              gap: 7,
              color: 'var(--text-muted)',
              fontSize: 10,
            }}
          >
            <DatabaseZap size={13} /> No application data is fabricated
          </div>
        </Panel>

        <Panel className="foundation-card">
          <div className="mono-label" style={{ color: 'var(--text-muted)' }}>Scope checkpoint</div>
          <div style={{ display: 'grid', gap: 4, marginTop: 20 }}>
            {foundationState.map((item) => (
              <div
                key={item.label}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '26px 1fr auto',
                  alignItems: 'center',
                  gap: 9,
                  minHeight: 48,
                  borderBottom: '1px solid var(--border-soft)',
                }}
              >
                {item.ready ? <Check size={15} color="var(--success)" /> : <CircleDashed size={15} color="var(--text-muted)" />}
                <span style={{ color: item.ready ? 'var(--text-main)' : 'var(--text-sub)', fontSize: 12 }}>{item.label}</span>
                <span className="mono-label" style={{ color: item.ready ? 'var(--success)' : 'var(--text-muted)', fontSize: 8 }}>{item.state}</span>
              </div>
            ))}
          </div>
          <p style={{ margin: '22px 0 0', color: 'var(--text-muted)', fontSize: 11, lineHeight: 1.65 }}>
            This task establishes presentation and navigation only. Backend integration and domain functionality remain intentionally untouched.
          </p>
        </Panel>
      </div>
    </div>
  )
}
