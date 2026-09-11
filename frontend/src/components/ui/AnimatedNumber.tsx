import { useEffect, useRef, useState } from 'react'

interface AnimatedNumberProps {
  value: number
  /** Formatter applied to every intermediate frame. */
  format: (value: number) => string
  durationMs?: number
}

/**
 * Counts up to a real value. Under `prefers-reduced-motion` (or when the value
 * is not finite) it renders the final value immediately — the animation is
 * decoration, never a precondition for reading the metric.
 */
export function AnimatedNumber({ value, format, durationMs = 620 }: AnimatedNumberProps) {
  const reduce =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches

  const [shown, setShown] = useState(() => (reduce ? value : 0))
  const frame = useRef<number>()

  useEffect(() => {
    if (reduce || !Number.isFinite(value)) {
      setShown(value)
      return
    }

    const start = performance.now()
    const from = 0

    const tick = (now: number) => {
      const progress = Math.min((now - start) / durationMs, 1)
      // easeOutCubic: fast settle, no bounce
      const eased = 1 - (1 - progress) ** 3
      setShown(from + (value - from) * eased)
      if (progress < 1) frame.current = requestAnimationFrame(tick)
    }

    frame.current = requestAnimationFrame(tick)
    return () => {
      if (frame.current) cancelAnimationFrame(frame.current)
    }
  }, [durationMs, reduce, value])

  return <span className="wx-num">{format(shown)}</span>
}
