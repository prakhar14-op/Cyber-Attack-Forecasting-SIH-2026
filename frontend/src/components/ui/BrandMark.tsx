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
          border: '1px solid rgba(56, 189, 248, 0.25)',
          borderRadius: 11,
          background: 'linear-gradient(145deg, rgba(56,189,248,.14), rgba(37,99,235,.06))',
          boxShadow: '0 0 24px rgba(56,189,248,.08)',
          color: 'var(--accent-bright)',
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
