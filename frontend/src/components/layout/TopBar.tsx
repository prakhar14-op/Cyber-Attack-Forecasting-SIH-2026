import { Clock3, ShieldCheck } from 'lucide-react'
import { useLocation } from 'react-router'

import { findNavigationItem } from '@/lib/navigation'
import { StatusBadge } from '@/components/ui/StatusBadge'

export function TopBar() {
  const { pathname } = useLocation()
  const activeItem = findNavigationItem(pathname)

  return (
    <header className="topbar">
      <div style={{ minWidth: 0 }}>
        <div className="mono-label" style={{ color: 'var(--text-muted)', fontSize: 9 }}>
          Network attack forecasting
        </div>
        <div style={{ marginTop: 3, overflow: 'hidden', fontSize: 14, fontWeight: 700, textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {activeItem?.label ?? 'Analyst workspace'}
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span className="mono-label" style={{ display: 'inline-flex', alignItems: 'center', gap: 7, color: 'var(--text-muted)', fontSize: 9 }}>
          <Clock3 size={13} /> Batch mode
        </span>
        <StatusBadge tone="success" pulse>
          <ShieldCheck size={12} /> Offline ready
        </StatusBadge>
      </div>
    </header>
  )
}
