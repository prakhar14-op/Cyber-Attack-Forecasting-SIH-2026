import type { RiskBand } from '@/features/graph/graphModel'

/**
 * Risk colours for the graph. Risk is *also* encoded by label and by the
 * numeric band shown in the legend, and host zone by shape — colour is never
 * the only carrier of meaning.
 */
export const RISK_COLOR: Record<RiskBand, string> = {
  quiet: '#7c8da6',
  alerting: '#f59e0b',
  high: '#ef4444',
}

export const EDGE_COLOR = {
  quiet: '#334155',
  risky: '#ef4444',
} as const

export const SCENE_BACKGROUND = '#0b1220'
