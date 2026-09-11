import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'

import { useAnalysisSession } from '@/services/analysisSessionContext'
import { ReplayContext } from '@/services/replayContext'
import type { ReplayValue } from '@/services/replayContext'

/** `configs/data.yaml :: windows` — the grid the engine scores on. */
const WINDOW_SECONDS = 15
const STRIDE_SECONDS = 5

/** Capture-seconds advanced per real second at 1x. */
const BASE_RATE = 20

const STORAGE_KEY = 'sih26.replay.cursor'

interface StoredCursor {
  runId: string
  cursor: number
}

function readStored(): StoredCursor | null {
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as StoredCursor) : null
  } catch {
    return null
  }
}

export function ReplayProvider({ children }: { children: ReactNode }) {
  const { session } = useAnalysisSession()

  const range = useMemo(() => {
    const forecasts = session?.result.forecasts ?? []
    const episodes = session?.annotation?.episodes ?? []
    if (forecasts.length === 0 && episodes.length === 0) return null

    const starts = [
      ...forecasts.map((forecast) => forecast.window_start),
      ...episodes.map((episode) => episode.start),
    ]
    const ends = [
      ...forecasts.map((forecast) => forecast.window_start + WINDOW_SECONDS),
      ...episodes.map((episode) => episode.end),
    ]
    return { start: Math.min(...starts), end: Math.max(...ends) }
  }, [session])

  // Restored synchronously so a hard navigation between /timeline and /graph
  // keeps the position. Doing this in an effect would race the persist effect.
  const restored = useState(() => readStored())[0]
  const restorable = restored && session && restored.runId === session.runId ? restored : null

  const [cursor, setCursorState] = useState<number | null>(restorable ? restorable.cursor : null)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const [engaged, setEngaged] = useState(Boolean(restorable))
  const frame = useRef<number>()
  const lastRunId = useRef(session?.runId ?? null)

  // A different analysis invalidates the old position.
  useEffect(() => {
    const runId = session?.runId ?? null
    if (runId === lastRunId.current) return
    lastRunId.current = runId
    setCursorState(null)
    setEngaged(false)
    setPlaying(false)
  }, [session?.runId])

  useEffect(() => {
    if (!session) return
    try {
      if (cursor === null || !engaged) {
        window.sessionStorage.removeItem(STORAGE_KEY)
      } else {
        window.sessionStorage.setItem(
          STORAGE_KEY,
          JSON.stringify({ runId: session.runId, cursor } satisfies StoredCursor),
        )
      }
    } catch {
      /* storage unavailable: in-memory sync still works */
    }
  }, [cursor, engaged, session])

  const clamp = useCallback(
    (time: number) => {
      if (!range) return time
      return Math.min(Math.max(time, range.start), range.end)
    },
    [range],
  )

  const setCursor = useCallback(
    (time: number) => {
      setEngaged(true)
      setCursorState(clamp(time))
    },
    [clamp],
  )

  const step = useCallback(
    (windows: number) => {
      if (!range) return
      setEngaged(true)
      setCursorState((current) => clamp((current ?? range.start) + windows * STRIDE_SECONDS))
    },
    [clamp, range],
  )

  const play = useCallback(() => {
    if (!range) return
    setEngaged(true)
    setCursorState((current) => (current === null || current >= range.end ? range.start : current))
    setPlaying(true)
  }, [range])

  const pause = useCallback(() => setPlaying(false), [])
  const toggle = useCallback(() => (playing ? pause() : play()), [pause, play, playing])

  const reset = useCallback(() => {
    setPlaying(false)
    setEngaged(false)
    setCursorState(null)
  }, [])

  // Playback advances capture time in real time; it stops at the end rather
  // than looping, so the completion marker is where the replay lands.
  useEffect(() => {
    if (!playing || !range) return

    let last = performance.now()
    const tick = (now: number) => {
      const deltaSeconds = (now - last) / 1000
      last = now
      let reachedEnd = false
      setCursorState((current) => {
        const next = (current ?? range.start) + deltaSeconds * BASE_RATE * speed
        if (next >= range.end) {
          reachedEnd = true
          return range.end
        }
        return next
      })
      if (reachedEnd) {
        setPlaying(false)
        return
      }
      frame.current = requestAnimationFrame(tick)
    }

    frame.current = requestAnimationFrame(tick)
    return () => {
      if (frame.current) cancelAnimationFrame(frame.current)
    }
  }, [playing, range, speed])

  const cursorWindow = useMemo(() => {
    if (cursor === null || !range) return null
    const offset = cursor - range.start
    return range.start + Math.floor(offset / STRIDE_SECONDS) * STRIDE_SECONDS
  }, [cursor, range])

  const value = useMemo<ReplayValue>(
    () => ({
      range,
      cursor,
      cursorWindow,
      playing,
      speed,
      engaged,
      setCursor,
      step,
      play,
      pause,
      toggle,
      setSpeed,
      reset,
    }),
    [
      cursor,
      cursorWindow,
      engaged,
      pause,
      play,
      playing,
      range,
      reset,
      setCursor,
      speed,
      step,
      toggle,
    ],
  )

  return <ReplayContext.Provider value={value}>{children}</ReplayContext.Provider>
}
