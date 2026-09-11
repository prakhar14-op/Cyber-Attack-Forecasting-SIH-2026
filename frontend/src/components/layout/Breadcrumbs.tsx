import { ChevronRight } from 'lucide-react'
import { Fragment } from 'react'
import { Link, useLocation, useParams } from 'react-router'

/**
 * Where the analyst is in the workflow. Trails follow the real navigation
 * graph — Analyze feeds the dashboard, the dashboard feeds investigation —
 * rather than the URL's literal segments.
 */
const TRAILS: Record<string, Array<{ label: string; to?: string }>> = {
  '/analyze': [{ label: 'Operations' }, { label: 'Analyze capture' }],
  '/dashboard': [{ label: 'Operations' }, { label: 'SOC dashboard' }],
  '/timeline': [
    { label: 'Operations' },
    { label: 'SOC dashboard', to: '/dashboard' },
    { label: 'Timeline' },
  ],
  '/graph': [
    { label: 'Investigation' },
    { label: 'SOC dashboard', to: '/dashboard' },
    { label: 'Attack graph' },
  ],
  '/explain': [{ label: 'Investigation' }, { label: 'Explainability' }],
  '/forecast': [{ label: 'Investigation' }, { label: 'Forecast horizons' }],
  '/ledger': [{ label: 'Investigation' }, { label: 'Audit ledger' }],
  '/benchmark': [{ label: 'Investigation' }, { label: 'Benchmark & evidence' }],
}

export function Breadcrumbs() {
  const { pathname } = useLocation()
  const { host } = useParams()

  const trail = pathname.startsWith('/incident')
    ? [
        { label: 'Investigation' },
        { label: 'SOC dashboard', to: '/dashboard' },
        { label: host ? decodeURIComponent(host) : 'Select host' },
      ]
    : TRAILS[pathname]

  if (!trail) return null

  return (
    <nav aria-label="Breadcrumb" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
      {trail.map((crumb, index) => (
        <Fragment key={`${crumb.label}-${index}`}>
          {index > 0 && (
            <ChevronRight size={11} aria-hidden="true" style={{ color: 'var(--c-text-muted)', opacity: 0.7 }} />
          )}
          {crumb.to ? (
            <Link
              className="wx-mono"
              to={crumb.to}
              style={{ color: 'var(--c-text-muted)', textDecoration: 'none' }}
            >
              {crumb.label}
            </Link>
          ) : (
            <span
              className="wx-mono"
              style={{ color: index === trail.length - 1 ? 'var(--c-text-sub)' : 'var(--c-text-muted)' }}
              aria-current={index === trail.length - 1 ? 'page' : undefined}
            >
              {crumb.label}
            </span>
          )}
        </Fragment>
      ))}
    </nav>
  )
}
