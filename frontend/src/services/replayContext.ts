import { createContext, useContext } from 'react'

/**
 * Replay position, shared by /timeline and /graph so the two stay in sync.
 *
 * `cursor` is capture time in epoch seconds. `cursorWindow` is that time
 * quantised to the window grid — consumers that are expensive to re-render
 * (the 3D scene) subscribe to the quantised value, so they update once per
 * window instead of once per animation frame.
 */
export interface ReplayValue {
  /** Full capture span of the analysed result, or null with no analysis. */
  range: { start: number; end: number } | null
  cursor: number | null
  /** `cursor` snapped down to the stride grid. */
  cursorWindow: number | null
  playing: boolean
  speed: number
  /** True once the analyst has moved or played time; the graph then dims. */
  engaged: boolean
  setCursor: (time: number) => void
  step: (windows: number) => void
  play: () => void
  pause: () => void
  toggle: () => void
  setSpeed: (speed: number) => void
  reset: () => void
}

export const ReplayContext = createContext<ReplayValue | null>(null)

export function useReplay(): ReplayValue {
  const value = useContext(ReplayContext)
  if (!value) throw new Error('useReplay must be used inside <ReplayProvider>')
  return value
}
