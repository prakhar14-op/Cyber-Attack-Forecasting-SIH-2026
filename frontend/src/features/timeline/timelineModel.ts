/**
 * Pure replay model for /timeline.
 *
 * Timing rules, stated because the honesty of this page depends on them:
 *
 * - The score track is built from `forecasts`, which contain only host-windows
 *   at or above the threshold. There is no sub-threshold score history in the
 *   result, so the track is an alert track and the page says so.
 * - **First alert** is the earliest alerting window — real, from the result.
 * - **Earliest evidence** is the oldest contributing window referenced by
 *   `top_windows[].seconds_before_alert`. That is the only precursor signal the
 *   result carries; it is not called an "anomaly score".
 * - **Attack completion** exists only in the capture's annotation. With no
 *   annotation there is no completion marker and no lead time — the page
 *   renders that absence instead of estimating.
 * - **Lead time** follows `eval/harness.py`: completion of an annotated episode
 *   minus the first alert on that episode's attacking host. Reported per episode
 *   plus the median, never averaged into a single invented number.
 */

import type {
  AnnotatedEpisode,
  AttackStage,
  CaptureAnnotation,
  Forecast,
  PredictionResult,
} from '@/types/backend'

const WINDOW_SECONDS = 15
const STRIDE_SECONDS = 5

export interface ReplayHost {
  host: string
  probability: number
  stage: AttackStage
  technique: string | null
  techniqueName: string
}

export interface ReplayWindow {
  start: number
  end: number
  /** Network score = max over hosts alerting in this window. */
  score: number
  topHost: string
  stage: AttackStage
  hosts: ReplayHost[]
}

export interface EpisodeLead {
  episode: string
  stage: AttackStage
  attacker: string
  firstAlert: number
  completion: number
  leadSeconds: number
}

export interface ReplayModel {
  windows: ReplayWindow[]
  range: { start: number; end: number }
  firstAlert: { time: number; host: string; probability: number; stage: AttackStage } | null
  earliestEvidence: { time: number; secondsBeforeFirstAlert: number } | null
  episodes: AnnotatedEpisode[]
  attackEpisodes: AnnotatedEpisode[]
  completion: number | null
  leads: EpisodeLead[]
  medianLeadSeconds: number | null
  annotationSource: string | null
  annotationNote: string | null
  /** Episodes whose attacking host never alerted — a miss, shown as such. */
  missedEpisodes: AnnotatedEpisode[]
}

function median(values: number[]): number | null {
  if (values.length === 0) return null
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  if (sorted.length % 2 === 1) return sorted[middle] ?? null
  return (((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2)
}

function firstAlertOnHost(forecasts: Forecast[], host: string): number | null {
  let earliest: number | null = null
  for (const forecast of forecasts) {
    if (forecast.host !== host) continue
    if (earliest === null || forecast.window_start < earliest) earliest = forecast.window_start
  }
  return earliest
}

export function buildReplayModel(
  result: PredictionResult,
  annotation: CaptureAnnotation | null,
): ReplayModel {
  const byWindow = new Map<number, Forecast[]>()
  for (const forecast of result.forecasts) {
    const list = byWindow.get(forecast.window_start) ?? []
    list.push(forecast)
    byWindow.set(forecast.window_start, list)
  }

  const windows: ReplayWindow[] = [...byWindow.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([start, forecasts]) => {
      const top = forecasts.reduce((best, f) => (f.probability > best.probability ? f : best))
      return {
        start,
        end: start + WINDOW_SECONDS,
        score: top.probability,
        topHost: top.host,
        stage: top.stage,
        hosts: forecasts
          .map((forecast) => ({
            host: forecast.host,
            probability: forecast.probability,
            stage: forecast.stage,
            technique: forecast.technique,
            techniqueName: forecast.technique_name,
          }))
          .sort((a, b) => b.probability - a.probability),
      }
    })

  const episodes = annotation?.episodes ?? []
  const attackEpisodes = episodes.filter((episode) => episode.stage !== 'benign')

  const starts = [
    ...windows.map((window) => window.start),
    ...episodes.map((episode) => episode.start),
  ]
  const ends = [...windows.map((window) => window.end), ...episodes.map((episode) => episode.end)]
  const range = {
    start: starts.length ? Math.min(...starts) : 0,
    end: ends.length ? Math.max(...ends) : STRIDE_SECONDS,
  }

  const firstWindow = windows[0]
  const firstAlert = firstWindow
    ? {
        time: firstWindow.start,
        host: firstWindow.topHost,
        probability: firstWindow.score,
        stage: firstWindow.stage,
      }
    : null

  let earliestEvidence: ReplayModel['earliestEvidence'] = null
  if (firstAlert) {
    const contributing = result.forecasts
      .filter((forecast) => forecast.window_start === firstAlert.time)
      .flatMap((forecast) => forecast.top_windows)
    if (contributing.length > 0) {
      const oldest = contributing.reduce((max, window) =>
        window.seconds_before_alert > max.seconds_before_alert ? window : max,
      )
      earliestEvidence = {
        time: oldest.window_start,
        secondsBeforeFirstAlert: oldest.seconds_before_alert,
      }
    }
  }

  const leads: EpisodeLead[] = []
  const missedEpisodes: AnnotatedEpisode[] = []
  for (const episode of attackEpisodes) {
    if (!episode.attacker) continue
    const alert = firstAlertOnHost(result.forecasts, episode.attacker)
    if (alert === null || alert > episode.end) {
      missedEpisodes.push(episode)
      continue
    }
    leads.push({
      episode: episode.name,
      stage: episode.stage,
      attacker: episode.attacker,
      firstAlert: alert,
      completion: episode.end,
      leadSeconds: episode.end - alert,
    })
  }

  return {
    windows,
    range,
    firstAlert,
    earliestEvidence,
    episodes,
    attackEpisodes,
    completion: attackEpisodes.length
      ? Math.max(...attackEpisodes.map((episode) => episode.end))
      : null,
    leads,
    medianLeadSeconds: median(leads.map((lead) => lead.leadSeconds)),
    annotationSource: annotation?.source ?? null,
    annotationNote: annotation?.note ?? null,
    missedEpisodes,
  }
}

export interface ReplaySlice {
  window: ReplayWindow | null
  /** Hosts alerting in the window under the cursor. */
  activeHosts: ReplayHost[]
  /** Hosts that have alerted at or before the cursor. */
  seenHosts: string[]
  /** Annotated episodes covering the cursor. */
  activeEpisodes: AnnotatedEpisode[]
  phase: 'before-first-alert' | 'alerting' | 'lead-window' | 'after-completion'
}

/** What is true at one instant of capture time. Pure lookup, no interpolation. */
export function replaySliceAt(model: ReplayModel, cursor: number): ReplaySlice {
  const window =
    model.windows.find((entry) => cursor >= entry.start && cursor < entry.start + STRIDE_SECONDS) ??
    null

  const seen = new Set<string>()
  for (const entry of model.windows) {
    if (entry.start > cursor) break
    for (const host of entry.hosts) seen.add(host.host)
  }

  const activeEpisodes = model.episodes.filter(
    (episode) => cursor >= episode.start && cursor <= episode.end,
  )

  let phase: ReplaySlice['phase'] = 'before-first-alert'
  if (model.firstAlert && cursor >= model.firstAlert.time) {
    phase = window ? 'alerting' : 'lead-window'
    if (model.completion !== null && cursor > model.completion) phase = 'after-completion'
  }

  return {
    window,
    activeHosts: window?.hosts ?? [],
    seenHosts: [...seen],
    activeEpisodes,
    phase,
  }
}
