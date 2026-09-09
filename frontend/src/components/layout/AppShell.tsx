import { useState } from 'react'
import { Outlet } from 'react-router'

import { MobileNav } from '@/components/layout/MobileNav'
import { Sidebar } from '@/components/layout/Sidebar'
import { TopBar } from '@/components/layout/TopBar'

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div className="app-frame">
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((value) => !value)} />
      <div className="app-main">
        <TopBar />
        <main className="app-content content-enter">
          <Outlet />
        </main>
      </div>
      <MobileNav />
    </div>
  )
}
