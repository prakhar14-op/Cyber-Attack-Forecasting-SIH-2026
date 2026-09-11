import { ShieldCheck } from 'lucide-react'

interface BrandMarkProps {
  compact?: boolean
}

export function BrandMark({ compact = false }: BrandMarkProps) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: compact ? 0 : 11 }}>
      <div
        aria-hidden="true"
        style={{
          display: 'grid',
          width: 36,
          height: 36,
          flex: '0 0 auto',
          placeItems: 'center',
          border: '1px solid var(--border-medium)',
          borderRadius: 11,
          background: 'var(--accent)',
          color: '#fff',
        }}
      >
        <ShieldCheck size={18} strokeWidth={1.8} />
      </div>
      {!compact && (
        <div>
          <div style={{ fontSize: 14, fontWeight: 800, letterSpacing: '-0.02em' }}>SENTINEL FORECAST</div>
          <div className="mono-label" style={{ marginTop: 2, color: 'var(--text-muted)', fontSize: 8 }}>
            SIH 2026 · NTRO
          </div>
        </div>
      )}
    </div>
  )
}
