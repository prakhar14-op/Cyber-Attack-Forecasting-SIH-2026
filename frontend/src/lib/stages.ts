import { STAGE_PALETTE } from '@/services/themeContext'
import type { Theme } from '@/services/themeContext'
import type { AttackStage } from '@/types/backend'

/**
 * One fixed meaning per stage, used everywhere a stage appears (badges, chart
 * markers, graph rings, legends).
 *
 * `stageColor` returns a CSS variable so a stage follows the active theme with
 * no re-render — the variables are defined per theme in `styles/console.css`.
 * Surfaces that are ALWAYS dark (the 3D scene, the replay track) and canvas
 * renderers that cannot resolve CSS variables use `stageHex` instead.
 */
export function stageColor(stage: AttackStage): string {
  return `var(--stage-${stage.replace(/_/g, '-')}, ${STAGE_PALETTE.light[stage]})`
}

/** Literal hex for three.js materials and always-dark surfaces. */
export function stageHex(stage: AttackStage, theme: Theme = 'dark'): string {
  return STAGE_PALETTE[theme][stage] ?? '#64748b'
}

export const STAGE_LABEL: Record<AttackStage, string> = {
  benign: 'Benign',
  recon: 'Recon',
  initial_access: 'Initial access',
  lateral_movement: 'Lateral movement',
  c2: 'Command & control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
}

export function stageLabel(stage: AttackStage): string {
  return STAGE_LABEL[stage] ?? stage
}
