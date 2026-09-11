import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import {
  CHART_PALETTE,
  RISK_PALETTE,
  STAGE_PALETTE,
  ThemeContext,
} from '@/services/themeContext'
import type { Theme, ThemeValue } from '@/services/themeContext'

const STORAGE_KEY = 'sih26.console.theme'

function initialTheme(): Theme {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    /* storage blocked: fall through to the OS preference */
  }
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(initialTheme)

  const set = useCallback((next: Theme) => {
    setTheme(next)
    try {
      window.localStorage.setItem(STORAGE_KEY, next)
    } catch {
      /* preference simply will not persist */
    }
  }, [])

  const toggle = useCallback(() => {
    set(theme === 'dark' ? 'light' : 'dark')
  }, [set, theme])

  // Drives the CSS token overrides and the native form/scrollbar colours.
  useEffect(() => {
    document.documentElement.dataset.consoleTheme = theme
    document.documentElement.style.colorScheme = theme
  }, [theme])

  const value = useMemo<ThemeValue>(
    () => ({
      theme,
      toggle,
      set,
      stageColors: STAGE_PALETTE[theme],
      chart: CHART_PALETTE[theme],
      risk: RISK_PALETTE[theme],
    }),
    [set, theme, toggle],
  )

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}
