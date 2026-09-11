/**
 * Pure graph model: turns `result.graph` into a deterministic 3D layout plus the
 * risk classification the scene and the legend both read.
 *
 * No data is invented. Nodes and edges are exactly what the pipeline emitted;
 * only positions are computed here, and they are computed from the topology
 * (which node connects to which), never from probabilities.
 */

import type { AttackStage, Forecast, GraphEdge, PredictionResult } from '@/types/backend'

export type RiskBand = 'quiet' | 'alerting' | 'high'
export type HostZone = 'internal' | 'external' | 'unknown'

export interface GraphNode3D {
  ip: string
  x: number
  y: number
  z: number
  peakProb: number
  alerts: number
  zone: HostZone
  risk: RiskBand
  /** Total flow weight touching this host — the size of its footprint. */
  degree: number
}

export interface GraphEdge3D extends GraphEdge {
  from: GraphNode3D
  to: GraphNode3D
  /** Normalised 0..1 flow weight, for line emphasis. */
  weightScale: number
}

export interface GraphModel {
  nodes: GraphNode3D[]
  edges: GraphEdge3D[]
  shown: number
  total: number
  truncated: boolean
  counts: { high: number; alerting: number; quiet: number; external: number }
  /** The boundary used for the `high` band, so the legend can state it. */
  highBand: number
  /** Radius of the laid-out cloud, used to frame the camera. */
  radius: number
}

/** Halfway between the alert threshold and certainty — stated in the legend. */
export function highRiskBoundary(threshold: number): number {
  return threshold + (1 - threshold) / 2
}

export function classifyRisk(peakProb: number, alerts: number, threshold: number): RiskBand {
  if (alerts === 0 || peakProb < threshold) return 'quiet'
  return peakProb >= highRiskBoundary(threshold) ? 'high' : 'alerting'
}

function zoneOf(internal: number | null): HostZone {
  if (internal === 1) return 'internal'
  if (internal === 0) return 'external'
  return 'unknown'
}

/** Deterministic PRNG (mulberry32) so a layout is identical on every load. */
function mulberry32(seed: number) {
  let a = seed
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

interface Vec3 {
  x: number
  y: number
  z: number
}

/**
 * Fruchterman–Reingold style layout in 3D: repulsion between every pair,
 * attraction along edges, linearly cooling step size. Seeded and iteration-
 * bounded, so it is stable, cheap and deterministic — the same role
 * `networkx.spring_layout(dim=3, seed=…)` plays on the Python side.
 */
function layout(ips: string[], links: Array<[string, string]>, iterations = 220): Map<string, Vec3> {
  const random = mulberry32(1337)
  const n = ips.length
  const positions = new Map<string, Vec3>()
  ips.forEach((ip) => {
    positions.set(ip, {
      x: random() * 2 - 1,
      y: random() * 2 - 1,
      z: random() * 2 - 1,
    })
  })

  if (n <= 1) return positions

  const k = 2.2 / Math.sqrt(n)
  const adjacency = links.filter(([a, b]) => a !== b)

  for (let step = 0; step < iterations; step += 1) {
    const temperature = 0.1 * (1 - step / iterations) + 0.002
    const forces = new Map<string, Vec3>(ips.map((ip) => [ip, { x: 0, y: 0, z: 0 }]))

    for (let i = 0; i < n; i += 1) {
      for (let j = i + 1; j < n; j += 1) {
        const a = ips[i] as string
        const b = ips[j] as string
        const pa = positions.get(a) as Vec3
        const pb = positions.get(b) as Vec3
        let dx = pa.x - pb.x
        let dy = pa.y - pb.y
        let dz = pa.z - pb.z
        let distance = Math.hypot(dx, dy, dz)
        if (distance < 1e-4) {
          dx = random() * 1e-3
          dy = random() * 1e-3
          dz = random() * 1e-3
          distance = Math.hypot(dx, dy, dz) || 1e-4
        }
        const repulsion = (k * k) / distance
        const fa = forces.get(a) as Vec3
        const fb = forces.get(b) as Vec3
        fa.x += (dx / distance) * repulsion
        fa.y += (dy / distance) * repulsion
        fa.z += (dz / distance) * repulsion
        fb.x -= (dx / distance) * repulsion
        fb.y -= (dy / distance) * repulsion
        fb.z -= (dz / distance) * repulsion
      }
    }

    // Attraction along topology only: every edge pulls equally, so a heavy
    // scan does not collapse its endpoints onto each other.
    for (const [src, dst] of adjacency) {
      const pa = positions.get(src)
      const pb = positions.get(dst)
      if (!pa || !pb) continue
      const dx = pa.x - pb.x
      const dy = pa.y - pb.y
      const dz = pa.z - pb.z
      const distance = Math.hypot(dx, dy, dz) || 1e-4
      const attraction = (distance * distance) / k
      const fa = forces.get(src) as Vec3
      const fb = forces.get(dst) as Vec3
      fa.x -= (dx / distance) * attraction
      fa.y -= (dy / distance) * attraction
      fa.z -= (dz / distance) * attraction
      fb.x += (dx / distance) * attraction
      fb.y += (dy / distance) * attraction
      fb.z += (dz / distance) * attraction
    }

    for (const ip of ips) {
      const position = positions.get(ip) as Vec3
      const force = forces.get(ip) as Vec3
      const magnitude = Math.hypot(force.x, force.y, force.z) || 1e-4
      const scale = Math.min(magnitude, temperature) / magnitude
      position.x += force.x * scale
      position.y += force.y * scale
      position.z += force.z * scale
    }
  }

  // Centre on the centroid, then normalise into a sphere of radius ~4.5 so the
  // camera framing is stable regardless of host count.
  let cx = 0
  let cy = 0
  let cz = 0
  for (const position of positions.values()) {
    cx += position.x
    cy += position.y
    cz += position.z
  }
  cx /= n
  cy /= n
  cz /= n

  let radius = 1e-4
  for (const position of positions.values()) {
    position.x -= cx
    position.y -= cy
    position.z -= cz
    radius = Math.max(radius, Math.hypot(position.x, position.y, position.z))
  }
  const scale = 4.5 / radius
  for (const position of positions.values()) {
    position.x *= scale
    position.y *= scale
    position.z *= scale
  }
  return positions
}

export function buildGraphModel(
  result: PredictionResult,
  maxNodes = 160,
): GraphModel {
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
  const keptEdges = result.graph.edges.filter(
    (edge) => keptIps.has(edge.src) && keptIps.has(edge.dst),
  )

  const positions = layout(
    kept.map((node) => node.ip),
    keptEdges.map((edge) => [edge.src, edge.dst] as [string, string]),
  )

  const nodes: GraphNode3D[] = kept.map((node) => {
    const position = positions.get(node.ip) ?? { x: 0, y: 0, z: 0 }
    return {
      ip: node.ip,
      x: position.x,
      y: position.y,
      z: position.z,
      peakProb: node.peak_prob,
      alerts: node.n_alerts,
      zone: zoneOf(node.internal),
      risk: classifyRisk(node.peak_prob, node.n_alerts, result.threshold),
      degree: degree.get(node.ip) ?? 0,
    }
  })

  const byIp = new Map(nodes.map((node) => [node.ip, node]))
  const maxWeight = keptEdges.reduce((max, edge) => Math.max(max, edge.weight), 1)

  const edges: GraphEdge3D[] = keptEdges.flatMap((edge) => {
    const from = byIp.get(edge.src)
    const to = byIp.get(edge.dst)
    if (!from || !to) return []
    return [{ ...edge, from, to, weightScale: edge.weight / maxWeight }]
  })

  return {
    nodes,
    edges,
    shown: nodes.length,
    total: result.graph.nodes.length,
    truncated: result.graph.nodes.length > nodes.length,
    counts: {
      high: nodes.filter((node) => node.risk === 'high').length,
      alerting: nodes.filter((node) => node.risk === 'alerting').length,
      quiet: nodes.filter((node) => node.risk === 'quiet').length,
      external: nodes.filter((node) => node.zone === 'external').length,
    },
    highBand: highRiskBoundary(result.threshold),
    radius: nodes.reduce((max, node) => Math.max(max, Math.hypot(node.x, node.y, node.z)), 1),
  }
}

export interface HostEvidence {
  stages: AttackStage[]
  dominantStage: AttackStage | null
  technique: string | null
  techniqueName: string | null
  peakForecast: Forecast | null
  firstWindow: number | null
  lastWindow: number | null
}

/** Everything the inspector shows about a host, read straight from forecasts. */
export function hostEvidence(result: PredictionResult, host: string): HostEvidence {
  const forecasts = result.forecasts.filter((forecast) => forecast.host === host)
  if (forecasts.length === 0) {
    return {
      stages: [],
      dominantStage: null,
      technique: null,
      techniqueName: null,
      peakForecast: null,
      firstWindow: null,
      lastWindow: null,
    }
  }

  const counts = new Map<AttackStage, number>()
  for (const forecast of forecasts) {
    counts.set(forecast.stage, (counts.get(forecast.stage) ?? 0) + 1)
  }
  const dominantStage =
    [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0] ?? null

  const peakForecast = forecasts.reduce((best, f) => (f.probability > best.probability ? f : best))

  return {
    stages: [...counts.keys()],
    dominantStage,
    technique: peakForecast.technique,
    techniqueName: peakForecast.technique_name,
    peakForecast,
    firstWindow: forecasts.reduce((min, f) => Math.min(min, f.window_start), Infinity),
    lastWindow: forecasts.reduce((max, f) => Math.max(max, f.window_start), -Infinity),
  }
}
