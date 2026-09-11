/** Presentation-only formatting. No business logic. */

const INT = new Intl.NumberFormat('en-US')

export function formatInt(value: number): string {
  return INT.format(Math.round(value))
}

export function formatBytes(bytes: number | null): string {
  if (bytes === null || Number.isNaN(bytes)) return '—'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`
}

/** Fixed 4 decimals — thresholds and probabilities are compared by eye. */
export function formatProbability(value: number): string {
  return value.toFixed(4)
}

export function formatPercent(value: number, digits = 1): string {
  return `${(value * 100).toFixed(digits)}%`
}

export function formatSeconds(seconds: number): string {
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`
  if (seconds < 60) return `${seconds.toFixed(1)} s`
  const minutes = Math.floor(seconds / 60)
  return `${minutes}m ${Math.round(seconds % 60)}s`
}

/** Epoch seconds -> UTC clock, the unit window_start is expressed in. */
export function formatWindowStart(epochSeconds: number): string {
  return `${new Date(epochSeconds * 1000).toISOString().slice(11, 19)}Z`
}

export function fileExtension(name: string): string {
  const index = name.lastIndexOf('.')
  return index === -1 ? '' : name.slice(index).toLowerCase()
}
