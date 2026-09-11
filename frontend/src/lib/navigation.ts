import {
  Activity,
  Binary,
  ChartNoAxesCombined,
  FileSearch,
  Gauge,
  GitBranch,
  Network,
  Radar,
  ScanSearch,
  ScrollText,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

export interface NavigationItem {
  label: string
  shortLabel: string
  path: string
  icon: LucideIcon
  accent: string
}

export interface NavigationGroup {
  label: string
  items: NavigationItem[]
}

export const navigationGroups: NavigationGroup[] = [
  {
    label: 'Operations',
    items: [
      { label: 'Analyze Capture', shortLabel: 'Analyze', path: '/analyze', icon: ScanSearch, accent: '#38bdf8' },
      { label: 'SOC Dashboard', shortLabel: 'Dashboard', path: '/dashboard', icon: Gauge, accent: '#38bdf8' },
      { label: 'Attack Graph', shortLabel: 'Graph', path: '/graph', icon: Network, accent: '#a78bfa' },
      { label: 'Forecast', shortLabel: 'Forecast', path: '/forecast', icon: Radar, accent: '#7dd3fc' },
      { label: 'Timeline', shortLabel: 'Timeline', path: '/timeline', icon: Activity, accent: '#60a5fa' },
    ],
  },
  {
    label: 'Investigation',
    items: [
      { label: 'Incident Workspace', shortLabel: 'Incident', path: '/incident', icon: FileSearch, accent: '#f59e0b' },
      { label: 'Explainability', shortLabel: 'Explain', path: '/explain', icon: Binary, accent: '#a78bfa' },
      { label: 'Audit Ledger', shortLabel: 'Ledger', path: '/ledger', icon: ScrollText, accent: '#34d399' },
      { label: 'Benchmark', shortLabel: 'Benchmark', path: '/benchmark', icon: ChartNoAxesCombined, accent: '#94a3b8' },
    ],
  },
]

export const navigationItems = navigationGroups.flatMap((group) => group.items)

export function findNavigationItem(pathname: string): NavigationItem | undefined {
  return navigationItems.find((item) => {
    if (item.path.startsWith('/incident/')) {
      return pathname.startsWith('/incident/')
    }
    return item.path === pathname
  })
}

export const workflowSteps = [
  { label: 'Capture', icon: ScanSearch },
  { label: 'Host windows', icon: GitBranch },
  { label: 'Forecast', icon: Radar },
  { label: 'Evidence', icon: ScrollText },
] as const
