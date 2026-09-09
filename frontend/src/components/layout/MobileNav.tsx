import { NavLink } from 'react-router'

import { navigationItems } from '@/lib/navigation'

export function MobileNav() {
  return (
    <nav className="mobile-nav" aria-label="Mobile navigation">
      {navigationItems.map((item) => (
        <NavLink key={item.path} to={item.path} aria-label={item.label} title={item.shortLabel}>
          <item.icon size={19} strokeWidth={1.8} />
        </NavLink>
      ))}
    </nav>
  )
}
