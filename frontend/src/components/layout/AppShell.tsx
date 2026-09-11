import { useState } from 'react'
import { Outlet, useLocation } from 'react-router'

import { MobileNav } from '@/components/layout/MobileNav'
import { Sidebar } from '@/components/layout/Sidebar'
import { TopBar } from '@/components/layout/TopBar'
import { AnalysisSessionProvider } from '@/services/AnalysisSessionProvider'
import { ReplayProvider } from '@/services/ReplayProvider'
import { ThemeProvider } from '@/services/ThemeProvider'
import '@/styles/console.css'

export function AppShell() {
  const [collapsed, setCollapsed] = useState(false)
  const { pathname } = useLocation()

  return (
    <ThemeProvider>
      <AnalysisSessionProvider>
        <ReplayProvider>
          <div className="app-frame console-surface">
            <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((value) => !value)} />
            <div className="app-main">
              <TopBar />
              {/* keyed so the enter transition replays on each navigation */}
              <main className="app-content content-enter" key={pathname}>
                <Outlet />
              </main>
            </div>
            <MobileNav />
          </div>
        </ReplayProvider>
      </AnalysisSessionProvider>
    </ThemeProvider>
  )
}
