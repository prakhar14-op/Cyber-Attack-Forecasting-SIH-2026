import type { CSSProperties, ReactNode } from 'react'

interface PanelProps {
  children: ReactNode
  className?: string
  style?: CSSProperties
}

export function Panel({ children, className = '', style }: PanelProps) {
  return (
    <section className={`glass-panel ${className}`.trim()} style={style}>
      {children}
    </section>
  )
}
