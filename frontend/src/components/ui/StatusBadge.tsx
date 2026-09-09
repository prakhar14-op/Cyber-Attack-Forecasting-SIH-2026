import type { ReactNode } from 'react'

interface StatusBadgeProps {
  children: ReactNode
  tone?: 'neutral' | 'success' | 'accent' | 'warning'
  pulse?: boolean
}

const toneColors = {
  neutral: 'var(--text-muted)',
  success: 'var(--success)',
  accent: 'var(--accent)',
  warning: 'var(--warning)',
} as const

export function StatusBadge({ children, tone = 'neutral', pulse = false }: StatusBadgeProps) {
  const color = toneColors[tone]

  return (
    <span
      className="mono-label"
      style={{
        display: 'inline-flex',
        minHeight: 28,
        alignItems: 'center',
        gap: 8,
        border: `1px solid color-mix(in srgb, ${color} 24%, transparent)`,
        borderRadius: 999,
        padding: '0 10px',
        background: `color-mix(in srgb, ${color} 7%, transparent)`,
        color,
        fontSize: 9,
      }}
    >
      {pulse && <span className="status-dot" style={{ background: color }} aria-hidden="true" />}
      {children}
    </span>
  )
}
