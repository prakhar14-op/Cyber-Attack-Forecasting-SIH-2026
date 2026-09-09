import { lazy } from 'react'
import { createBrowserRouter, Navigate } from 'react-router'

import { AppShell } from '@/components/layout/AppShell'
import { RouteBoundary } from '@/components/ui/RouteBoundary'

const LandingPage = lazy(() => import('@/pages/LandingPage'))
const AnalyzePage = lazy(() => import('@/pages/AnalyzePage'))
const DashboardPage = lazy(() => import('@/pages/DashboardPage'))
const GraphPage = lazy(() => import('@/pages/GraphPage'))
const ForecastPage = lazy(() => import('@/pages/ForecastPage'))
const TimelinePage = lazy(() => import('@/pages/TimelinePage'))
const IncidentPage = lazy(() => import('@/pages/IncidentPage'))
const ExplainPage = lazy(() => import('@/pages/ExplainPage'))
const LedgerPage = lazy(() => import('@/pages/LedgerPage'))
const BenchmarkPage = lazy(() => import('@/pages/BenchmarkPage'))

export const router = createBrowserRouter([
  {
    path: '/',
    element: <RouteBoundary><LandingPage /></RouteBoundary>,
  },
  {
    element: <AppShell />,
    children: [
      { path: '/analyze', element: <RouteBoundary><AnalyzePage /></RouteBoundary> },
      { path: '/dashboard', element: <RouteBoundary><DashboardPage /></RouteBoundary> },
      { path: '/graph', element: <RouteBoundary><GraphPage /></RouteBoundary> },
      { path: '/forecast', element: <RouteBoundary><ForecastPage /></RouteBoundary> },
      { path: '/timeline', element: <RouteBoundary><TimelinePage /></RouteBoundary> },
      { path: '/incident/:host', element: <RouteBoundary><IncidentPage /></RouteBoundary> },
      { path: '/explain', element: <RouteBoundary><ExplainPage /></RouteBoundary> },
      { path: '/ledger', element: <RouteBoundary><LedgerPage /></RouteBoundary> },
      { path: '/benchmark', element: <RouteBoundary><BenchmarkPage /></RouteBoundary> },
    ],
  },
  { path: '*', element: <Navigate to="/" replace /> },
])
