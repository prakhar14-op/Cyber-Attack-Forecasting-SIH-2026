import { Clock3, FileCheck2, FileQuestion, Moon, Sun, WifiOff } from 'lucide-react'
import { Link, useLocation } from 'react-router'

import { Breadcrumbs } from '@/components/layout/Breadcrumbs'
import { findNavigationItem } from '@/lib/navigation'
import { useAnalysisSession } from '@/services/analysisSessionContext'
import { useTheme } from '@/services/themeContext'

export function TopBar() {
  const { pathname } = useLocation()
  const activeItem = findNavigationItem(pathname)
  const { session } = useAnalysisSession()
  const { theme, toggle } = useTheme()

  return (
    <header className="topbar">
      <div style={{ minWidth: 0 }}>
        <Breadcrumbs />
        <div
          style={{
            marginTop: 3,
            overflow: 'hidden',
            fontSize: 14,
            fontWeight: 700,
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {activeItem?.label ?? 'Analyst workspace'}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {/* One shared indicator of what capture the whole console is describing. */}
        {session ? (
          <Link className="wx-pill wx-mono tone-info" to="/dashboard" style={{ textDecoration: 'none' }}>
            <FileCheck2 size={12} aria-hidden="true" /> {session.input.name}
          </Link>
        ) : (
          <Link className="wx-pill wx-mono" to="/analyze" style={{ textDecoration: 'none' }}>
            <FileQuestion size={12} aria-hidden="true" /> no capture loaded
          </Link>
        )}

        <span className="wx-pill wx-mono">
          <Clock3 size={12} aria-hidden="true" /> batch
        </span>
        <span className="wx-pill wx-mono tone-ok">
          <WifiOff size={12} aria-hidden="true" /> offline
        </span>

        <button
          type="button"
          className="wx-btn"
          onClick={toggle}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          style={{ minHeight: 30, padding: '0 10px' }}
        >
          {theme === 'dark' ? <Sun size={14} aria-hidden="true" /> : <Moon size={14} aria-hidden="true" />}
        </button>
      </div>
    </header>
  )
}
