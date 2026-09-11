import { Suspense } from 'react'
import type { ReactNode } from 'react'

import { ErrorBoundary } from '@/components/ui/ErrorBoundary'

interface RouteBoundaryProps {
  children: ReactNode
}

export function RouteBoundary({ children }: RouteBoundaryProps) {
  return (
    <ErrorBoundary>
      <Suspense
        fallback={(
          <div style={{ display: 'grid', minHeight: '40vh', placeItems: 'center' }}>
            <div className="mono-label" style={{ color: 'var(--text-muted)' }}>Loading local module…</div>
          </div>
        )}
      >
        {children}
      </Suspense>
    </ErrorBoundary>
  )
}
