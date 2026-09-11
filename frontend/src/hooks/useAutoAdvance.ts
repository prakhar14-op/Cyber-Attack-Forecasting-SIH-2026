import { useCallback, useEffect, useRef, useState } from 'react'

const TICK_MS = 100

/**
 * Counts down while `active`, then fires once. Returns the remaining seconds so
 * the UI can show what is about to happen, and a `cancel` so the analyst can
 * stop it. Nothing runs while `active` is false — no idle timers.
 */
export function useAutoAdvance(active: boolean, delayMs: number, onFire: () => void) {
  const [remaining, setRemaining] = useState<number | null>(null)
  const [cancelled, setCancelled] = useState(false)
  const fire = useRef(onFire)
  fire.current = onFire

  useEffect(() => {
    if (!active) {
      setCancelled(false)
      setRemaining(null)
      return
    }
    if (cancelled) return

    let left = delayMs
    setRemaining(left / 1000)
    const timer = setInterval(() => {
      left -= TICK_MS
      if (left <= 0) {
        clearInterval(timer)
        setRemaining(null)
        fire.current()
        return
      }
      setRemaining(left / 1000)
    }, TICK_MS)

    return () => clearInterval(timer)
  }, [active, cancelled, delayMs])

  const cancel = useCallback(() => {
    setCancelled(true)
    setRemaining(null)
  }, [])

  return { remaining, cancel }
}
