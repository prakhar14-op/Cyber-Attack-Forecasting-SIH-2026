import { Pause, Play, RotateCcw, SkipBack, SkipForward, ZoomIn, ZoomOut } from 'lucide-react'

import { formatWindowStart } from '@/lib/format'

const SPEEDS = [0.5, 1, 2, 4] as const

interface ReplayControlsProps {
  playing: boolean
  speed: number
  cursor: number | null
  windowStart: number | null
  zoom: number
  onToggle: () => void
  onStep: (windows: number) => void
  onSpeed: (speed: number) => void
  onZoom: (zoom: number) => void
  onReset: () => void
}

export function ReplayControls({
  playing,
  speed,
  cursor,
  windowStart,
  zoom,
  onToggle,
  onStep,
  onSpeed,
  onZoom,
  onReset,
}: ReplayControlsProps) {
  return (
    <div className="replay-controls">
      <button type="button" className="replay-btn is-active" onClick={onToggle} aria-pressed={playing}>
        {playing ? <Pause size={13} aria-hidden="true" /> : <Play size={13} aria-hidden="true" />}
        {playing ? 'Pause' : 'Play'}
      </button>
      <button type="button" className="replay-btn" onClick={() => onStep(-1)} aria-label="Previous window">
        <SkipBack size={13} aria-hidden="true" /> −1 win
      </button>
      <button type="button" className="replay-btn" onClick={() => onStep(1)} aria-label="Next window">
        <SkipForward size={13} aria-hidden="true" /> +1 win
      </button>

      <span className="replay-btn" style={{ borderStyle: 'dashed', cursor: 'default' }}>
        speed
      </span>
      {SPEEDS.map((option) => (
        <button
          key={option}
          type="button"
          className={`replay-btn${option === speed ? ' is-active' : ''}`}
          aria-pressed={option === speed}
          onClick={() => onSpeed(option)}
        >
          {option}×
        </button>
      ))}

      <button
        type="button"
        className="replay-btn"
        onClick={() => onZoom(Math.min(zoom * 2, 16))}
        aria-label="Zoom in"
        disabled={zoom >= 16}
      >
        <ZoomIn size={13} aria-hidden="true" />
      </button>
      <button
        type="button"
        className="replay-btn"
        onClick={() => onZoom(Math.max(zoom / 2, 1))}
        aria-label="Zoom out"
        disabled={zoom <= 1}
      >
        <ZoomOut size={13} aria-hidden="true" />
      </button>
      <button type="button" className="replay-btn" onClick={onReset}>
        <RotateCcw size={13} aria-hidden="true" /> Reset
      </button>

      <span className="replay-readout">
        cursor <b>{cursor === null ? '—' : formatWindowStart(cursor)}</b>
        {' · '}window <b>{windowStart === null ? 'none' : formatWindowStart(windowStart)}</b>
        {' · '}zoom <b>{zoom}×</b>
      </span>
    </div>
  )
}
