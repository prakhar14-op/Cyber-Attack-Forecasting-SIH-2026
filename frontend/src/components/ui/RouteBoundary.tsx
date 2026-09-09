import { Suspense } from 'react'
import type { ReactNode } from 'react'

interface RouteBoundaryProps {
  children: ReactNode
}

export function RouteBoundary({ children }: RouteBoundaryProps) {
  return (
    <Suspense
      fallback={(
        <div style={{ display: 'grid', minHeight: '40vh', placeItems: 'center' }}>
          <div className="mono-label" style={{ color: 'var(--text-muted)' }}>Loading local module…</div>
        </div>
      )}
    >
      {children}
    </Suspense>
  )
}
