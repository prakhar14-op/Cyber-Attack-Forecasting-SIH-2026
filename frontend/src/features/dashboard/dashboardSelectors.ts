/**
 * Pure derivations over a `PredictionResult`. No UI, no fetching, no invented
 * values: every function here only aggregates fields the pipeline produced.
 *
 * Two properties of the real result shape the whole dashboard, and the UI states
 * both rather than papering over them:
 *
 * 1. `forecasts` contains ONLY host-windows at or above the threshold. Windows
 *    below it are not in the result, so a network-score timeline drawn from this
 *    data is an *alert* timeline, not a full score history.
 * 2. `estimated_lead_seconds` is `null` for a single-file run — lead time is
 *    measured against annotated episode completion by `eval/harness.py`, which
 *    is eval-side. The only real timing evidence in the result is
 *    `top_windows[].seconds_before_alert`: how far back the contributing
 *    precursor windows reach. That is reported as a precursor span and never
 *    labelled "lead time".
 */

import type { AttackStage, Forecast, GraphEdge, PredictionResult } from '@/types/backend'

export interface HostRow {
  host: string
  peakProbability: number
  alerts: number
  dominantStage: AttackStage
  /** Widest `seconds_before_alert` seen on this host, or null if none. */
  precursorSpanSeconds: number | null
  /** The alert that drives this host's rank. */
  peakForecast: Forecast
  internal: number | null
}

export interface TimelinePoint {
  windowStart: number
  /** Network score = max over hosts in the window (fixed decision). */
  networkScore: number
  /** The host holding the max, so a spike is attributable. */
  host: string
  stage: AttackStage
  hostsAlerting: number
}

export interface StageCount {
  stage: AttackStage
  alerts: number
  share: number
}

export interface LeadEvidence {
  seconds: number | null
  basis: 'engine' | 'precursor' | 'unavailable'
  note: string
}

export function peakProbability(result: PredictionResult): number | null {
  if (result.forecasts.length === 0) return null
  return result.forecasts.reduce((max, f) => Math.max(max, f.probability), 0)
}

function widestPrecursor(forecasts: Forecast[]): number | null {
  let widest: number | null = null
  for (const forecast of forecasts) {
    for (const window of forecast.top_windows) {
      if (widest === null || window.seconds_before_alert > widest) {
        widest = window.seconds_before_alert
      }
    }
  }
  return widest
}

/**
 * Lead-time evidence, in order of authority: the engine's own value when it is
 * present, otherwise the observed precursor span, otherwise nothing.
 */
export function leadEvidence(result: PredictionResult): LeadEvidence {
  const engineValues = result.forecasts
    .map((f) => f.estimated_lead_seconds)
    .filter((value): value is number => value !== null)

  if (engineValues.length > 0) {
    const sorted = [...engineValues].sort((a, b) => a - b)
    const middle = Math.floor(sorted.length / 2)
    const median =
      sorted.length % 2 === 0
        ? ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2
        : (sorted[middle] ?? 0)
    return {
      seconds: median,
      basis: 'engine',
      note: 'Median estimated_lead_seconds across alerts, as reported by the engine.',
    }
  }

  const span = widestPrecursor(result.forecasts)
  if (span !== null) {
    return {
      seconds: span,
      basis: 'precursor',
      note: 'Widest seconds_before_alert among contributing windows. The engine leaves estimated_lead_seconds null for a single capture — true lead time is measured against annotated attack completion in eval/harness.py.',
    }
  }

  return {
    seconds: null,
    basis: 'unavailable',
    note: 'No alert carries timing evidence in this result.',
  }
}

export function hostRanking(result: PredictionResult): HostRow[] {
  const grouped = new Map<string, Forecast[]>()
  for (const forecast of result.forecasts) {
    const list = grouped.get(forecast.host) ?? []
    list.push(forecast)
    grouped.set(forecast.host, list)
  }

  const internalByHost = new Map(result.graph.nodes.map((node) => [node.ip, node.internal]))

  const rows: HostRow[] = []
  for (const [host, forecasts] of grouped) {
    const peakForecast = forecasts.reduce((best, f) => (f.probability > best.probability ? f : best))

    const stageCounts = new Map<AttackStage, number>()
    for (const forecast of forecasts) {
      stageCounts.set(forecast.stage, (stageCounts.get(forecast.stage) ?? 0) + 1)
    }
    const dominantStage = [...stageCounts.entries()].sort(
      (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
    )[0]?.[0]

    rows.push({
      host,
      peakProbability: peakForecast.probability,
      alerts: forecasts.length,
      dominantStage: dominantStage ?? peakForecast.stage,
      precursorSpanSeconds: widestPrecursor(forecasts),
      peakForecast,
      internal: internalByHost.get(host) ?? null,
    })
  }

  return rows.sort((a, b) => b.peakProbability - a.peakProbability || b.alerts - a.alerts)
}

export function threatTimeline(result: PredictionResult): TimelinePoint[] {
  const byWindow = new Map<number, Forecast[]>()
  for (const forecast of result.forecasts) {
    const list = byWindow.get(forecast.window_start) ?? []
    list.push(forecast)
    byWindow.set(forecast.window_start, list)
  }

  return [...byWindow.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([windowStart, forecasts]) => {
      const top = forecasts.reduce((best, f) => (f.probability > best.probability ? f : best))
      return {
        windowStart,
        networkScore: top.probability,
        host: top.host,
        stage: top.stage,
        hostsAlerting: new Set(forecasts.map((f) => f.host)).size,
      }
    })
}

export function stageDistribution(result: PredictionResult): StageCount[] {
  const counts = new Map<AttackStage, number>()
  for (const forecast of result.forecasts) {
    counts.set(forecast.stage, (counts.get(forecast.stage) ?? 0) + 1)
  }
  const total = result.forecasts.length || 1
  return [...counts.entries()]
    .map(([stage, alerts]) => ({ stage, alerts, share: alerts / total }))
    .sort((a, b) => b.alerts - a.alerts)
}

export interface ProgressionStep {
  stage: AttackStage
  firstWindow: number
  lastWindow: number
  alerts: number
  isCurrent: boolean
}

/**
 * Observed stage sequence, ordered by when each stage first fired. The result
 * carries no k-step stage prediction, so no step is ever marked "predicted" —
 * the UI says that explicitly instead of implying a forecast direction.
 */
export function attackProgression(result: PredictionResult): ProgressionStep[] {
  const seen = new Map<AttackStage, { first: number; last: number; alerts: number }>()
  for (const forecast of result.forecasts) {
    const entry = seen.get(forecast.stage)
    if (!entry) {
      seen.set(forecast.stage, {
        first: forecast.window_start,
        last: forecast.window_start,
        alerts: 1,
      })
      continue
    }
    entry.first = Math.min(entry.first, forecast.window_start)
    entry.last = Math.max(entry.last, forecast.window_start)
    entry.alerts += 1
  }

  const latestWindow = result.forecasts.reduce(
    (max, f) => Math.max(max, f.window_start),
    Number.NEGATIVE_INFINITY,
  )

  return [...seen.entries()]
    .sort((a, b) => a[1].first - b[1].first)
    .map(([stage, entry]) => ({
      stage,
      firstWindow: entry.first,
      lastWindow: entry.last,
      alerts: entry.alerts,
      isCurrent: entry.last === latestWindow,
    }))
}

export interface PreviewNode {
  ip: string
  x: number
  y: number
  peakProb: number
  alerts: number
  internal: number | null
  degree: number
}

export interface NetworkPreview {
  nodes: PreviewNode[]
  edges: Array<GraphEdge & { x0: number; y0: number; x1: number; y1: number }>
  shown: number
  total: number
  truncated: boolean
}

/**
 * A deterministic 2D preview of `result.graph`, ranked by risk and trimmed for
 * readability. Trimming is reported (`shown`/`total`/`truncated`) so the UI can
 * say what it dropped — never a silent hide. The flagship 3D layout lives on
 * /graph.
 */
export function networkPreview(result: PredictionResult, maxNodes = 18): NetworkPreview {
  const degree = new Map<string, number>()
  for (const edge of result.graph.edges) {
    degree.set(edge.src, (degree.get(edge.src) ?? 0) + edge.weight)
    degree.set(edge.dst, (degree.get(edge.dst) ?? 0) + edge.weight)
  }

  const ranked = [...result.graph.nodes].sort(
    (a, b) =>
      b.peak_prob - a.peak_prob ||
      b.n_alerts - a.n_alerts ||
      (degree.get(b.ip) ?? 0) - (degree.get(a.ip) ?? 0),
  )
  const kept = ranked.slice(0, maxNodes)
  const keptIps = new Set(kept.map((node) => node.ip))

  // Risk-ordered ring: the riskiest node sits at the centre, the rest orbit it
  // in rank order. Deterministic, no physics, no randomness.
  const positions = new Map<string, { x: number; y: number }>()
  kept.forEach((node, index) => {
    if (index === 0) {
      positions.set(node.ip, { x: 0.5, y: 0.5 })
      return
    }
    const orbitCount = Math.max(kept.length - 1, 1)
    const angle = (2 * Math.PI * (index - 1)) / orbitCount - Math.PI / 2
    const radius = 0.34 + 0.05 * ((index - 1) % 2)
    positions.set(node.ip, {
      x: 0.5 + radius * Math.cos(angle),
      y: 0.5 + radius * Math.sin(angle) * 0.86,
    })
  })

  const nodes: PreviewNode[] = kept.map((node) => {
    const position = positions.get(node.ip) ?? { x: 0.5, y: 0.5 }
    return {
      ip: node.ip,
      x: position.x,
      y: position.y,
      peakProb: node.peak_prob,
      alerts: node.n_alerts,
      internal: node.internal,
      degree: degree.get(node.ip) ?? 0,
    }
  })

  const edges = result.graph.edges
    .filter((edge) => keptIps.has(edge.src) && keptIps.has(edge.dst))
    .map((edge) => {
      const from = positions.get(edge.src) ?? { x: 0.5, y: 0.5 }
      const to = positions.get(edge.dst) ?? { x: 0.5, y: 0.5 }
      return { ...edge, x0: from.x, y0: from.y, x1: to.x, y1: to.y }
    })

  return {
    nodes,
    edges,
    shown: kept.length,
    total: result.graph.nodes.length,
    truncated: result.graph.nodes.length > kept.length,
  }
}
