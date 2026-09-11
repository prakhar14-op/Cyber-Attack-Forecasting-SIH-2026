import React, { useState, useMemo, useCallback } from 'react'

interface RippleGridProps {
  rows?: number
  cols?: number
  cellSize?: number
  color?: string  // Base color for ripple effect
}

const RippleGrid: React.FC<RippleGridProps> = ({ rows = 12, cols = 26, cellSize = 56, color = '16,185,129' }) => {
  const [ripple, setRipple] = useState<{ row: number; col: number; key: number } | null>(null)
  const cells = useMemo(() => Array.from({ length: rows * cols }, (_, i) => i), [rows, cols])

  const handleClick = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect()
    setRipple({
      row: Math.floor((e.clientY - rect.top) / cellSize),
      col: Math.floor((e.clientX - rect.left) / cellSize),
      key: Date.now(),
    })
  }, [cellSize])

  return (
    <div style={{
      position: 'absolute', inset: 0, overflow: 'hidden', zIndex: 0, pointerEvents: 'auto',
    }}>
      <style>{`
        @keyframes cellPulse-${color.replace(/,/g, '')} {
          0% { background: rgba(${color},0.22); transform: scale(0.88); }
          100% { background: transparent; transform: scale(1); }
        }
      `}</style>
      <div
        onClick={handleClick}
        style={{
          display: 'grid', cursor: 'crosshair',
          gridTemplateColumns: `repeat(${cols}, ${cellSize}px)`,
          gridTemplateRows: `repeat(${rows}, ${cellSize}px)`,
          width: cols * cellSize, marginInline: 'auto',
        }}
      >
        {cells.map((idx) => {
          const r = Math.floor(idx / cols)
          const c = idx % cols
          const dist = ripple ? Math.hypot(ripple.row - r, ripple.col - c) : -1
          const shouldAnimate = ripple && dist >= 0
          return (
            <div
              key={shouldAnimate ? `${ripple.key}-${idx}` : idx}
              style={{
                width: cellSize, height: cellSize,
                border: `1px solid rgba(${color},0.12)`,
                borderRadius: 2,
                transition: 'background 80ms',
                animation: shouldAnimate ? `cellPulse-${color.replace(/,/g, '')} ${120 + dist * 40}ms ${dist * 25}ms ease-out forwards` : 'none',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = `rgba(${color},0.08)` }}
              onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent' }}
            />
          )
        })}
      </div>
    </div>
  )
}

export default RippleGrid
