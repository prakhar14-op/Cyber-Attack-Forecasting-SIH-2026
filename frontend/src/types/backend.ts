/**
 * The backend data contract, in one place.
 *
 * `PredictionResult` mirrors the Python result dict returned by
 * `engine/predict.py :: predict_file` (and therefore `app/panels.run_pipeline`)
 * field for field — see .kiro/steering/architecture.md. Nothing here is
 * invented: if a field is not produced by the pipeline, it does not exist here.
 *
 * `AnalysisRun` describes the run envelope the frontend expects from the local
 * engine service (the loopback bridge that wraps `run_pipeline`). The service is
 * a separate backend surface; this file is the frontend's side of the contract.
 */

/** The 7 stage classes, in `configs/data.yaml` order. Order is the encoding. */
export const ATTACK_STAGES = [
  'benign',
  'recon',
  'initial_access',
  'lateral_movement',
  'c2',
  'exfiltration',
  'impact',
] as const

export type AttackStage = (typeof ATTACK_STAGES)[number]

export interface TopFeature {
  /** A real named window feature, e.g. `distinct_dst_ips`. Never an index. */
  feature: string
  value: number
  contribution: number
}

export interface TopWindow {
  window_start: number
  probability: number
  seconds_before_alert: number
}

export interface FlaggedFlow {
  dst_port: number
  protocol: number
  bytes: number
  syn: number
  duration_us: number
}

export interface Forecast {
  host: string
  window_start: number
  probability: number
  stage: AttackStage
  technique: string | null
  technique_name: string
  top_features: TopFeature[]
  top_windows: TopWindow[]
  flagged_flows: FlaggedFlow[]
  estimated_lead_seconds: number | null
}

export interface GraphNode {
  ip: string
  peak_prob: number
  n_alerts: number
  internal: number | null
}

export interface GraphEdge {
  src: string
  dst: string
  weight: number
  risk: number
}

export interface PredictionResult {
  n_flows: number
  n_host_windows: number
  n_alerts: number
  threshold: number
  forecasts: Forecast[]
  graph: { nodes: GraphNode[]; edges: GraphEdge[] }
}

/** `app/panels.py :: what_if_remove_host` */
export interface WhatIfResult {
  removed_host: string
  after: PredictionResult
}

/**
 * Ground-truth episode annotation for a capture. This is NOT part of
 * `predict_file` output — it comes from the capture's operator log
 * (`capture/label_capture.py` format, e.g.
 * `app/assets/synthetic_demo.operator-log.txt`) or, for dataset days, from
 * `data/attack_timeline.yaml`. It is the only source of an attack *completion*
 * time, and therefore the only basis for lead time. When a capture has no
 * annotation, lead time is not computable and must not be shown.
 */
export interface AnnotatedEpisode {
  name: string
  stage: AttackStage
  attacker: string | null
  victim: string | null
  /** Epoch seconds. */
  start: number
  end: number
}

export interface CaptureAnnotation {
  /** Repository path the intervals came from. */
  source: string
  note: string
  episodes: AnnotatedEpisode[]
}

/** `app/panels.py :: ledger_status` */
export interface LedgerStatus {
  exists: boolean
  records?: number
  verified?: boolean
  first_bad_index?: number | null
  anchored?: boolean
}

/* ------------------------------------------------------------------ */
/* Run envelope                                                        */
/* ------------------------------------------------------------------ */

/** The six presented pipeline stages. */
export type PipelineStageId =
  | 'capture'
  | 'features'
  | 'model'
  | 'forecast'
  | 'explanation'
  | 'ledger'

/**
 * A stage is `done` only when the backend reports it done. The UI never
 * advances a stage on a timer.
 */
export type PipelineStageState = 'pending' | 'active' | 'done' | 'failed' | 'skipped'

export interface StageEvidence {
  label: string
  /** Already-formatted, backend-produced value. */
  value: string
}

export interface PipelineStageReport {
  id: PipelineStageId
  state: PipelineStageState
  /** Real backend output that proves the stage ran. Empty until it does. */
  evidence: StageEvidence[]
  started_at: number | null
  finished_at: number | null
}

export type RunState = 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'

export type CaptureKind = 'pcap' | 'csv'

/** `full` = 30-feature PCAP path, `flow` = flow-only CSV path (decision 001). */
export type EngineVariant = 'full' | 'flow'

export interface RunInput {
  name: string
  bytes: number
  kind: CaptureKind
  engine_variant: EngineVariant
  sha256: string | null
  source: string
}

export interface RunSummary {
  n_flows: number
  n_host_windows: number
  n_alerts: number
  threshold: number
  fpr_budget: number
  ledger: LedgerStatus | null
}

export interface RunError {
  type: string
  message: string
  hint: string | null
}

export interface AnalysisRun {
  id: string
  state: RunState
  input: RunInput
  fpr_budget: number
  stages: PipelineStageReport[]
  summary: RunSummary | null
  error: RunError | null
  cancellable: boolean
  notes: string[]
}

/* ------------------------------------------------------------------ */
/* Service health                                                      */
/* ------------------------------------------------------------------ */

export interface MissingArtifact {
  artifact: string
  purpose: string
}

export interface EngineState {
  ready: boolean
  artifacts_dir: string
  missing_artifacts: MissingArtifact[]
  missing_modules: string[]
  bootstrap_hint: string | null
}

export interface PipelineConfig {
  window_seconds: number
  stride_seconds: number
  forecast_horizon_windows: number
  stages: string[]
  fpr_budgets: number[]
  n_features: number | null
}

export interface EngineHealth {
  service: string
  engine: EngineState
  config: PipelineConfig | null
}

export interface DemoSource {
  id: string
  label: string
  /** Repository-relative path the engine will read. */
  path: string
  kind: CaptureKind
  engine_variant: EngineVariant
  detail: string
  available: boolean
  bytes: number | null
  build_hint: string | null
}
