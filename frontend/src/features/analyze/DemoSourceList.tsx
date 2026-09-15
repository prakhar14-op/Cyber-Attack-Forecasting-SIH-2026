import { Check, FileSpreadsheet, PackageOpen, Play } from 'lucide-react'

import { formatBytes } from '@/lib/format'
import type { DemoSource } from '@/types/backend'

interface DemoSourceListProps {
  sources: DemoSource[]
  selectedPath: string | null
  disabled: boolean
  onSelect: (source: DemoSource) => void
  onRunSource: (source: DemoSource) => void
}

export function DemoSourceList({
  sources,
  selectedPath,
  disabled,
  onSelect,
  onRunSource,
}: DemoSourceListProps) {
  return (
    <section className="wx-panel" aria-labelledby="wx-sources-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="wx-sources-title">
          Repository-bundled inputs
        </span>
        <span className="wx-mono">{sources.filter((source) => source.available).length} available</span>
      </div>

      <div className="wx-panel-body" style={{ display: 'grid', gap: 8 }}>
        {sources.map((source) => {
          const selected = selectedPath === source.path
          const Icon = source.kind === 'csv' ? FileSpreadsheet : PackageOpen
          return (
            <div key={source.id} style={{ display: 'grid', gap: 8 }}>
              <div
                className={`wx-row${selected ? ' is-selected' : ''}`}
                style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}
                onClick={() => onSelect(source)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1 }}>
                  <span className="wx-row-icon" aria-hidden="true">
                    <Icon size={16} strokeWidth={1.8} />
                  </span>
                  <span>
                    <strong style={{ display: 'block' }}>{source.label}</strong>
                    <small>{source.detail}</small>
                    <small className="wx-mono" style={{ display: 'block', marginTop: 4 }}>
                      {source.path} · {formatBytes(source.bytes)} ·{' '}
                      {source.engine_variant === 'full' ? 'full features' : 'flow-only'}
                    </small>
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="wx-mono" style={{ color: selected ? 'var(--c-accent)' : 'var(--c-text-muted)' }}>
                    {selected ? <Check size={15} aria-hidden="true" /> : source.kind.toUpperCase()}
                  </span>
                  <button
                    type="button"
                    className="wx-btn wx-mono is-primary"
                    disabled={disabled || !source.available}
                    onClick={(e) => {
                      e.stopPropagation()
                      onRunSource(source)
                    }}
                    style={{ padding: '6px 12px', fontSize: 12 }}
                    title={`Run analysis on ${source.label}`}
                  >
                    <Play size={12} aria-hidden="true" /> Run
                  </button>
                </div>
              </div>
              {!source.available && source.build_hint && (
                <p className="wx-mono" style={{ margin: 0, color: 'var(--c-text-muted)' }}>
                  Not in this checkout — build with <code>{source.build_hint}</code>
                </p>
              )}
            </div>
          )
        })}

        {sources.some((source) => source.available) && (() => {
          const targetSource = sources.find((s) => s.path === selectedPath && s.available) || sources.find((s) => s.available)
          return targetSource ? (
            <button
              type="button"
              className="wx-btn is-primary"
              disabled={disabled}
              onClick={() => onRunSource(targetSource)}
              style={{ justifySelf: 'start', marginTop: 6 }}
            >
              <Play size={14} aria-hidden="true" /> Run analysis: {targetSource.label}
            </button>
          ) : null
        })()}
      </div>
    </section>
  )
}
