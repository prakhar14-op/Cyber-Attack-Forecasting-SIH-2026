/**
 * DEMO FIXTURE — NOT ENGINE OUTPUT.
 *
 * The real values on this page come from the offline Python pipeline
 * (`engine/predict.py :: predict_file`). That pipeline is not reachable from the
 * browser without the local engine service, so this module produces a
 * stand-in result **in the exact shape of the real contract** so the demo
 * workflow can be walked end to end.
 *
 * Rules this fixture follows so it stays honest and swappable:
 *
 * - Every consumer of this data renders the `DEMO FIXTURE` marker. The UI never
 *   presents these numbers as engine output.
 * - Feature names are the real 30 window features from `configs/data.yaml`
 *   (`packet_features.fields` + `packet_features.sent_fields` + role features).
 *   No embedding indices, no invented feature names.
 * - MITRE techniques follow `engine/technique_map.yaml` for the stage and
 *   feature pattern shown.
 * - The scenario is the one `capture/make_synthetic_demo.py` actually writes
 *   into `app/assets/synthetic_demo.pcap`: benign warm-up, sequential port
 *   recon, SSH brute force, internal pivot sweep, bulk outbound transfer —
 *   with that script's hosts and offsets.
 * - The CSV fixture respects decision 001: a flow CSV cannot carry packet
 *   statistics, so its explanations only cite window-bounded sent-side and role
 *   features.
 *
 * Replacing this module with a real service call requires no UI change: the
 * `AnalysisEngine` seam in `services/analysisEngine.ts` is the only touch point.
 */

import type {
  AttackStage,
  CaptureAnnotation,
  DemoSource,
  FlaggedFlow,
  Forecast,
  GraphEdge,
  GraphNode,
  LedgerStatus,
  PredictionResult,
  TopFeature,
  TopWindow,
} from '@/types/backend'

/** `configs/data.yaml :: windows` — the fixed decisions the engine uses. */
const WINDOW_SECONDS = 15
const STRIDE_SECONDS = 5
const MAX_CONTEXT_SECONDS = 48 * STRIDE_SECONDS

/** `capture/make_synthetic_demo.py` — fixed epoch, deterministic windows. */
const PCAP_BASE_EPOCH = 1_760_000_000
const ATTACKER = '203.0.113.7'
const VICTIM = '10.20.0.10'
const PIVOT = '10.20.0.20'
const BENIGN_HOSTS = ['10.20.0.100', '10.20.0.101', '10.20.0.102']

/** mini.csv is a 1,000-row excerpt of the 20-02-2018 day (README). */
const CSV_BASE_EPOCH = 1_519_034_400
const CSV_ATTACKER = '18.218.115.60'
const CSV_VICTIM = '172.31.69.25'

export const DEMO_SOURCES: DemoSource[] = [
  {
    id: 'synthetic_pcap',
    label: 'Synthetic demo capture',
    path: 'app/assets/synthetic_demo.pcap',
    kind: 'pcap',
    engine_variant: 'full',
    detail:
      'Deterministic hand-authored kill chain: benign warm-up, sequential port recon, SSH brute force, internal pivot sweep, bulk outbound transfer. Illustrative only — never used for a reported metric.',
    available: true,
    bytes: 4_652_064,
    build_hint: 'python -m capture.make_synthetic_demo',
  },
  {
    id: 'fixture_csv',
    label: 'Sample flow CSV',
    path: 'tests/fixtures/mini.csv',
    kind: 'csv',
    engine_variant: 'flow',
    detail:
      '1,000-row excerpt of CSE-CIC-IDS2018 20-02-2018 (benign + DDoS-LOIC-HTTP). Flow features only — a CSV cannot carry packet statistics (decision 001).',
    available: true,
    bytes: 476_437,
    build_hint: null,
  },
]

export function findDemoSource(id: string): DemoSource | undefined {
  return DEMO_SOURCES.find((source) => source.id === id)
}

/** Deterministic jitter in [0,1) — keeps the fixture stable across reloads. */
function jitter(seed: number): number {
  const x = Math.sin(seed * 127.1 + 311.7) * 43758.5453
  return x - Math.floor(x)
}

function ramp(index: number, count: number, from: number, to: number): number {
  if (count <= 1) return to
  return from + ((to - from) * index) / (count - 1)
}

function round(value: number, digits = 4): number {
  const factor = 10 ** digits
  return Math.round(value * factor) / factor
}

interface Phase {
  stage: AttackStage
  host: string
  peer: string
  /** Offsets in seconds from the capture base, as written by the generator. */
  startOffset: number
  endOffset: number
  probabilityFrom: number
  probabilityTo: number
  technique: string
  techniqueName: string
  internal: number
  features: (windowIndex: number) => TopFeature[]
  flows: (windowIndex: number) => FlaggedFlow[]
}

function feature(name: string, value: number, contribution: number): TopFeature {
  return { feature: name, value: round(value, 3), contribution: round(contribution, 3) }
}

/** Alert windows for a phase: window_start on the stride grid, fully inside it. */
function phaseWindows(phase: Phase): number[] {
  const first = Math.ceil(phase.startOffset / STRIDE_SECONDS) * STRIDE_SECONDS
  const last = phase.endOffset - WINDOW_SECONDS
  const out: number[] = []
  for (let offset = first; offset <= last; offset += STRIDE_SECONDS) out.push(offset)
  return out
}

const PCAP_PHASES: Phase[] = [
  {
    stage: 'recon',
    host: ATTACKER,
    peer: VICTIM,
    startOffset: 130,
    endOffset: 190,
    probabilityFrom: 0.7412,
    probabilityTo: 0.8963,
    technique: 'T1046',
    techniqueName: 'Network Service Discovery (sequential port sweep)',
    internal: 0,
    features: (i) => [
      feature('sequential_port_ratio', 0.98 + jitter(i) * 0.015, 1.94 + jitter(i + 1) * 0.2),
      feature('distinct_dst_ports', 206 + Math.floor(jitter(i + 2) * 9), 1.51),
      feature('syn', 212 + Math.floor(jitter(i + 3) * 7), 1.18),
      feature('port_entropy', 7.62 + jitter(i + 4) * 0.08, 0.74),
      feature('ack', 0, -0.41),
    ],
    flows: (i) => [
      { dst_port: 1 + i * 71, protocol: 6, bytes: 60, syn: 1, duration_us: 0 },
      { dst_port: 2 + i * 71, protocol: 6, bytes: 60, syn: 1, duration_us: 0 },
      { dst_port: 3 + i * 71, protocol: 6, bytes: 60, syn: 1, duration_us: 0 },
    ],
  },
  {
    stage: 'initial_access',
    host: ATTACKER,
    peer: VICTIM,
    startOffset: 200,
    endOffset: 260,
    probabilityFrom: 0.8317,
    probabilityTo: 0.9538,
    technique: 'T1110',
    techniqueName: 'Brute Force (credential guessing)',
    internal: 0,
    features: (i) => [
      feature('syn', 186 + Math.floor(jitter(i + 5) * 9), 2.21),
      feature('psh', 184 + Math.floor(jitter(i + 6) * 8), 1.36),
      feature('server_port_ratio', 1, 0.92),
      feature('payload_hist_1', 184 + Math.floor(jitter(i + 7) * 8), 0.63),
      feature('distinct_dst_ports', 1, -0.28),
    ],
    flows: (i) => [
      { dst_port: 22, protocol: 6, bytes: 95, syn: 1, duration_us: 10_000 + i * 120 },
      { dst_port: 22, protocol: 6, bytes: 95, syn: 1, duration_us: 10_400 + i * 120 },
      { dst_port: 22, protocol: 6, bytes: 95, syn: 1, duration_us: 10_800 + i * 120 },
    ],
  },
  {
    stage: 'lateral_movement',
    host: VICTIM,
    peer: PIVOT,
    startOffset: 270,
    endOffset: 320,
    probabilityFrom: 0.7684,
    probabilityTo: 0.9114,
    technique: 'T1046',
    techniqueName: 'Network Service Discovery (internal sweep)',
    internal: 1,
    features: (i) => [
      feature('distinct_dst_ports', 60 + Math.floor(jitter(i + 8) * 4), 1.72),
      feature('sequential_port_ratio', 0.96 + jitter(i + 9) * 0.02, 1.44),
      feature('internal', 1, 0.88),
      feature('syn', 60 + Math.floor(jitter(i + 10) * 4), 0.71),
      feature('distinct_dst_ips', 1, -0.34),
    ],
    flows: (i) => [
      { dst_port: 20 + i * 12, protocol: 6, bytes: 60, syn: 1, duration_us: 0 },
      { dst_port: 21 + i * 12, protocol: 6, bytes: 60, syn: 1, duration_us: 0 },
      { dst_port: 22 + i * 12, protocol: 6, bytes: 60, syn: 1, duration_us: 0 },
    ],
  },
  {
    stage: 'exfiltration',
    host: VICTIM,
    peer: ATTACKER,
    startOffset: 330,
    endOffset: 390,
    probabilityFrom: 0.9042,
    probabilityTo: 0.9871,
    technique: 'T1048',
    techniqueName: 'Exfiltration Over Alternative Protocol (large outbound transfer)',
    internal: 1,
    features: (i) => [
      feature('sent_bytes', 1_049_000 + Math.floor(jitter(i + 11) * 4000), 2.86),
      feature('sent_pkts', 748 + Math.floor(jitter(i + 12) * 6), 1.62),
      feature('payload_hist_6', 748 + Math.floor(jitter(i + 13) * 6), 1.21),
      feature('distinct_dst_ips', 1, 0.57),
      feature('syn', 0, -0.63),
    ],
    flows: () => [
      { dst_port: 4444, protocol: 6, bytes: 1_050_000, syn: 0, duration_us: 15_000_000 },
    ],
  },
]

const CSV_PHASES: Phase[] = [
  {
    stage: 'impact',
    host: CSV_ATTACKER,
    peer: CSV_VICTIM,
    startOffset: 0,
    endOffset: 55,
    probabilityFrom: 0.7628,
    probabilityTo: 0.8817,
    technique: 'T1498',
    techniqueName: 'Network Denial of Service',
    internal: 0,
    features: (i) => [
      feature('sent_pkts', 612 + Math.floor(jitter(i + 21) * 24), 2.04),
      feature('sent_bytes', 41_800 + Math.floor(jitter(i + 22) * 900), 1.27),
      feature('server_port_ratio', 1, 0.83),
      feature('distinct_dst_ips', 1, 0.44),
      feature('ack', 604 + Math.floor(jitter(i + 23) * 20), -0.31),
    ],
    flows: (i) => [
      { dst_port: 80, protocol: 6, bytes: 331, syn: 1, duration_us: 1_920_000 + i * 4300 },
      { dst_port: 80, protocol: 6, bytes: 331, syn: 1, duration_us: 2_040_000 + i * 4300 },
    ],
  },
]

function buildForecasts(phases: Phase[], baseEpoch: number): Forecast[] {
  const raw = phases.flatMap((phase) => {
    const windows = phaseWindows(phase)
    return windows.map((offset, index) => ({
      phase,
      windowStart: baseEpoch + offset,
      probability: round(
        ramp(index, windows.length, phase.probabilityFrom, phase.probabilityTo) +
          jitter(offset) * 0.006,
      ),
      index,
    }))
  })

  const history = new Map<string, Array<[number, number]>>()
  for (const row of raw) {
    const list = history.get(row.phase.host) ?? []
    list.push([row.windowStart, row.probability])
    history.set(row.phase.host, list)
  }

  return raw.map((row) => {
    const topWindows: TopWindow[] = (history.get(row.phase.host) ?? [])
      .filter(([start]) => start <= row.windowStart && start >= row.windowStart - MAX_CONTEXT_SECONDS)
      .sort((a, b) => b[1] - a[1] || b[0] - a[0])
      .slice(0, 3)
      .map(([start, probability]) => ({
        window_start: start,
        probability,
        seconds_before_alert: row.windowStart - start,
      }))

    return {
      host: row.phase.host,
      window_start: row.windowStart,
      probability: row.probability,
      stage: row.phase.stage,
      technique: row.phase.technique,
      technique_name: row.phase.techniqueName,
      top_features: row.phase.features(row.index),
      top_windows: topWindows,
      flagged_flows: row.phase.flows(row.index),
      estimated_lead_seconds: null,
    }
  })
}

function buildGraph(
  forecasts: Forecast[],
  edges: GraphEdge[],
  internalByHost: Record<string, number>,
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const peak = new Map<string, number>()
  const alerts = new Map<string, number>()
  for (const forecast of forecasts) {
    peak.set(forecast.host, Math.max(peak.get(forecast.host) ?? 0, forecast.probability))
    alerts.set(forecast.host, (alerts.get(forecast.host) ?? 0) + 1)
  }

  const hosts = new Set<string>([...peak.keys()])
  for (const edge of edges) {
    hosts.add(edge.src)
    hosts.add(edge.dst)
  }

  const nodes: GraphNode[] = [...hosts].sort().map((ip) => ({
    ip,
    peak_prob: peak.get(ip) ?? 0,
    n_alerts: alerts.get(ip) ?? 0,
    internal: internalByHost[ip] ?? null,
  }))

  return {
    nodes,
    edges: edges.map((edge) => ({ ...edge, risk: peak.get(edge.src) ?? 0 })),
  }
}

export interface DemoRunFixture {
  result: PredictionResult
  ledger: LedgerStatus
  /** Ground-truth episodes, or null when the capture has no annotation. */
  annotation: CaptureAnnotation | null
  /** Values the engine derives from the input, shown as CAPTURE evidence. */
  capture: { flows: number; hostWindows: number; featureCount: number }
}

/**
 * The synthetic capture's operator log, verbatim from
 * `app/assets/synthetic_demo.operator-log.txt` (written by
 * `capture/make_synthetic_demo.py` in `capture/label_capture.py`'s format).
 * Offsets are relative to the generator's fixed base epoch, so these are the
 * same instants the log records.
 */
const PCAP_ANNOTATION: CaptureAnnotation = {
  source: 'app/assets/synthetic_demo.operator-log.txt',
  note: 'Operator log of the synthetic capture — the annotated ground truth for this file. Lead time is measured against these completion times, the same definition eval/harness.py uses.',
  episodes: [
    { name: 'benign', stage: 'benign', attacker: null, victim: null, start: 0, end: 120 },
    { name: 'recon', stage: 'recon', attacker: ATTACKER, victim: VICTIM, start: 130, end: 190 },
    {
      name: 'initial_access',
      stage: 'initial_access',
      attacker: ATTACKER,
      victim: VICTIM,
      start: 200,
      end: 260,
    },
    {
      name: 'lateral_movement',
      stage: 'lateral_movement',
      attacker: VICTIM,
      victim: PIVOT,
      start: 270,
      end: 320,
    },
    {
      name: 'exfiltration',
      stage: 'exfiltration',
      attacker: VICTIM,
      victim: ATTACKER,
      start: 330,
      end: 390,
    },
  ].map((episode) => ({
    ...episode,
    stage: episode.stage as AttackStage,
    start: PCAP_BASE_EPOCH + episode.start,
    end: PCAP_BASE_EPOCH + episode.end,
  })),
}

function pcapFixture(fprBudget: number): DemoRunFixture {
  const forecasts = buildForecasts(PCAP_PHASES, PCAP_BASE_EPOCH)
  const edges: GraphEdge[] = [
    { src: ATTACKER, dst: VICTIM, weight: 1300, risk: 0 },
    { src: VICTIM, dst: ATTACKER, weight: 1, risk: 0 },
    { src: VICTIM, dst: PIVOT, weight: 200, risk: 0 },
    ...BENIGN_HOSTS.flatMap((host) => [
      { src: host, dst: VICTIM, weight: 47, risk: 0 },
      { src: VICTIM, dst: host, weight: 40, risk: 0 },
    ]),
  ]
  const internalByHost: Record<string, number> = {
    [ATTACKER]: 0,
    [VICTIM]: 1,
    [PIVOT]: 1,
    ...Object.fromEntries(BENIGN_HOSTS.map((host) => [host, 1])),
  }

  return {
    result: {
      n_flows: 1781,
      n_host_windows: 175,
      n_alerts: forecasts.length,
      threshold: fprBudget === 0.001 ? 0.8124 : 0.6931,
      forecasts,
      graph: buildGraph(forecasts, edges, internalByHost),
    },
    ledger: {
      exists: true,
      records: forecasts.length,
      verified: true,
      first_bad_index: null,
      anchored: true,
    },
    annotation: PCAP_ANNOTATION,
    capture: { flows: 1781, hostWindows: 175, featureCount: 30 },
  }
}

function csvFixture(fprBudget: number): DemoRunFixture {
  const forecasts = buildForecasts(CSV_PHASES, CSV_BASE_EPOCH)
  const edges: GraphEdge[] = [
    { src: CSV_ATTACKER, dst: CSV_VICTIM, weight: 891, risk: 0 },
    { src: CSV_VICTIM, dst: CSV_ATTACKER, weight: 74, risk: 0 },
    { src: '172.31.69.28', dst: CSV_VICTIM, weight: 21, risk: 0 },
  ]
  const internalByHost: Record<string, number> = {
    [CSV_ATTACKER]: 0,
    [CSV_VICTIM]: 1,
    '172.31.69.28': 1,
  }

  return {
    result: {
      n_flows: 1000,
      n_host_windows: 96,
      n_alerts: forecasts.length,
      threshold: fprBudget === 0.001 ? 0.8902 : 0.7413,
      forecasts,
      graph: buildGraph(forecasts, edges, internalByHost),
    },
    ledger: {
      exists: true,
      records: forecasts.length,
      verified: true,
      first_bad_index: null,
      anchored: true,
    },
    // data/attack_timeline.yaml carries no 2018-02-20 entry (that day is
    // fixture-only, not a model day), so this capture has no annotated
    // completion time and lead time is genuinely not computable for it.
    annotation: null,
    capture: { flows: 1000, hostWindows: 96, featureCount: 30 },
  }
}

export function demoFixtureFor(sourceId: string, fprBudget: number): DemoRunFixture {
  return sourceId === 'fixture_csv' ? csvFixture(fprBudget) : pcapFixture(fprBudget)
}
