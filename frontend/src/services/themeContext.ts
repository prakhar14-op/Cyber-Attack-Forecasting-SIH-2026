import { createContext, useContext } from 'react'

import type { AttackStage } from '@/types/backend'

export type Theme = 'light' | 'dark'

/**
 * Stage hues per theme. The mapping stage -> meaning never changes; only the
 * lightness is shaded so contrast holds on both surfaces. Light values are the
 * landing palette; dark values are the design-system stage colours.
 */
export const STAGE_PALETTE: Record<Theme, Record<AttackStage, string>> = {
  light: {
    benign: '#059669',
    recon: '#0284c7',
    initial_access: '#7c3aed',
    lateral_movement: '#b45309',
    c2: '#db2777',
    exfiltration: '#be123c',
    impact: '#dc2626',
  },
  dark: {
    benign: '#34d399',
    recon: '#38bdf8',
    initial_access: '#a78bfa',
    lateral_movement: '#f59e0b',
    c2: '#fb7185',
    exfiltration: '#f43f5e',
    impact: '#ef4444',
  },
}

/** Risk bands for the attack graph, shaded per theme. */
export const RISK_PALETTE: Record<Theme, { quiet: string; alerting: string; high: string }> = {
  light: { quiet: '#7c8da6', alerting: '#b45309', high: '#dc2626' },
  dark: { quiet: '#7c8da6', alerting: '#f59e0b', high: '#ef4444' },
}

/** Chart chrome (axes, grid, tooltips) so 2D charts follow the surface. */
export const CHART_PALETTE: Record<
  Theme,
  {
    grid: string
    tick: string
    axis: string
    tooltipBg: string
    tooltipBorder: string
    tooltipText: string
    accent: string
    danger: string
    dotStroke: string
  }
> = {
  light: {
    grid: 'rgba(45,38,28,.07)',
    tick: '#7e8594',
    axis: 'rgba(45,38,28,.2)',
    tooltipBg: '#ffffff',
    tooltipBorder: 'rgba(45,38,28,.12)',
    tooltipText: '#181a1d',
    accent: '#2563eb',
    danger: '#e11d48',
    dotStroke: '#ffffff',
  },
  dark: {
    grid: 'rgba(148,163,184,.14)',
    tick: '#94a3b8',
    axis: 'rgba(148,163,184,.3)',
    tooltipBg: '#111f36',
    tooltipBorder: 'rgba(148,163,184,.28)',
    tooltipText: '#e8f0fe',
    accent: '#38bdf8',
    danger: '#f87171',
    dotStroke: '#0f1c30',
  },
}

export interface ThemeValue {
  theme: Theme
  toggle: () => void
  set: (theme: Theme) => void
  /** Stage colours for the active theme. */
  stageColors: Record<AttackStage, string>
  chart: (typeof CHART_PALETTE)['light']
  risk: (typeof RISK_PALETTE)['light']
}

export const ThemeContext = createContext<ThemeValue | null>(null)

export function useTheme(): ThemeValue {
  const value = useContext(ThemeContext)
  if (!value) throw new Error('useTheme must be used inside <ThemeProvider>')
  return value
}
