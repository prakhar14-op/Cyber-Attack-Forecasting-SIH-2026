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
              <button
                type="button"
                className={`wx-row${selected ? ' is-selected' : ''}`}
                disabled={disabled || !source.available}
                aria-pressed={selected}
                onClick={() => onSelect(source)}
              >
                <span className="wx-row-icon" aria-hidden="true">
                  <Icon size={16} strokeWidth={1.8} />
                </span>
                <span>
                  <strong>{source.label}</strong>
                  <small>{source.detail}</small>
                  <small className="wx-mono" style={{ marginTop: 6 }}>
                    {source.path} · {formatBytes(source.bytes)} ·{' '}
                    {source.engine_variant === 'full' ? 'full features' : 'flow-only'}
                  </small>
                </span>
                <span className="wx-mono" style={{ color: selected ? 'var(--c-accent)' : 'var(--c-text-muted)' }}>
                  {selected ? <Check size={15} aria-hidden="true" /> : source.kind.toUpperCase()}
                </span>
              </button>
              {!source.available && source.build_hint && (
                <p className="wx-mono" style={{ margin: 0, color: 'var(--c-text-muted)' }}>
                  Not in this checkout — build with <code>{source.build_hint}</code>
                </p>
              )}
            </div>
          )
        })}

        {sources.some((source) => source.available) && (
          <button
            type="button"
            className="wx-btn"
            disabled={disabled}
            onClick={() => {
              const first = sources.find((source) => source.available)
              if (first) onRunSource(first)
            }}
            style={{ justifySelf: 'start', marginTop: 2 }}
          >
            <Play size={14} aria-hidden="true" /> Run demo capture
          </button>
        )}
      </div>
    </section>
  )
}
