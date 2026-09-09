import { AnimatePresence, motion } from 'motion/react'
import { ChevronLeft, ChevronRight, House, RadioTower } from 'lucide-react'
import type { CSSProperties } from 'react'
import { NavLink } from 'react-router'

import { navigationGroups } from '@/lib/navigation'
import { BrandMark } from '@/components/ui/BrandMark'

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const width = collapsed ? 84 : 272

  return (
    <motion.aside
      className="sidebar"
      animate={{ width }}
      transition={{ type: 'spring', stiffness: 320, damping: 32 }}
      aria-label="Primary navigation"
    >
      <div
        className="sidebar-header"
        style={{ justifyContent: collapsed ? 'center' : 'space-between', padding: collapsed ? 0 : '0 16px' }}
      >
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={collapsed ? 'compact' : 'full'}
            initial={{ opacity: 0, x: -5 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -5 }}
          >
            <BrandMark compact={collapsed} />
          </motion.div>
        </AnimatePresence>
        {!collapsed && (
          <button
            type="button"
            onClick={onToggle}
            aria-label="Collapse navigation"
            style={{
              display: 'grid',
              width: 30,
              height: 30,
              placeItems: 'center',
              border: '1px solid var(--border-soft)',
              borderRadius: 9,
              background: 'transparent',
              color: 'var(--text-muted)',
              cursor: 'pointer',
            }}
          >
            <ChevronLeft size={15} />
          </button>
        )}
      </div>

      {collapsed && (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '9px 0 2px' }}>
          <button
            type="button"
            onClick={onToggle}
            aria-label="Expand navigation"
            style={{
              display: 'grid',
              width: 30,
              height: 30,
              placeItems: 'center',
              border: 0,
              borderRadius: 9,
              background: 'transparent',
              color: 'var(--text-muted)',
              cursor: 'pointer',
            }}
          >
            <ChevronRight size={15} />
          </button>
        </div>
      )}

      <nav style={{ flex: 1, overflowY: 'auto', padding: collapsed ? '10px 11px' : '14px 12px' }}>
        <NavLink
          to="/"
          title={collapsed ? 'Mission overview' : undefined}
          className={({ isActive }) => `nav-link${isActive ? ' nav-link-active' : ''}`}
          style={{
            '--nav-accent': '#7dd3fc',
            justifyContent: collapsed ? 'center' : 'flex-start',
            gap: 11,
            padding: collapsed ? 0 : '0 12px',
            marginBottom: 16,
          } as CSSProperties}
        >
          <House size={17} strokeWidth={1.8} />
          {!collapsed && <span style={{ fontSize: 13, fontWeight: 650 }}>Mission overview</span>}
        </NavLink>

        {navigationGroups.map((group) => (
          <div key={group.label} style={{ marginBottom: 18 }}>
            {!collapsed && (
              <div className="mono-label" style={{ padding: '0 10px 7px', color: 'var(--text-muted)', fontSize: 9 }}>
                {group.label}
              </div>
            )}
            <div style={{ display: 'grid', gap: 3 }}>
              {group.items.map((item) => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  title={collapsed ? item.label : undefined}
                  className={({ isActive }) => `nav-link${isActive ? ' nav-link-active' : ''}`}
                  style={{
                    '--nav-accent': item.accent,
                    justifyContent: collapsed ? 'center' : 'flex-start',
                    gap: 11,
                    padding: collapsed ? 0 : '0 12px',
                  } as CSSProperties}
                >
                  <item.icon size={17} strokeWidth={1.8} style={{ flex: '0 0 auto' }} />
                  {!collapsed && <span style={{ fontSize: 13, fontWeight: 620 }}>{item.label}</span>}
                </NavLink>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div style={{ borderTop: '1px solid var(--border-soft)', padding: collapsed ? 12 : 14 }}>
        <div
          title={collapsed ? 'Local offline workspace' : undefined}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: collapsed ? 'center' : 'flex-start',
            gap: 10,
            border: '1px solid rgba(52, 211, 153, 0.12)',
            borderRadius: 12,
            padding: collapsed ? '11px 0' : '11px 12px',
            background: 'rgba(52, 211, 153, 0.04)',
          }}
        >
          <RadioTower size={16} color="var(--success)" />
          {!collapsed && (
            <div>
              <div className="mono-label" style={{ color: 'var(--success)', fontSize: 9 }}>Local workspace</div>
              <div style={{ marginTop: 3, color: 'var(--text-muted)', fontSize: 10 }}>No external services</div>
            </div>
          )}
        </div>
      </div>
    </motion.aside>
  )
}
