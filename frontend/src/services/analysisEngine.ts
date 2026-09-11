/**
 * The single seam between the /analyze UI and whatever executes the pipeline.
 *
 * Today the only implementation is `demoEngine` (see `demo/fixtureCaptures.ts`),
 * which produces a **labelled fixture** in the exact shape of the Python result
 * dict. When the local engine service exists, implement `AnalysisEngine` against
 * it and swap `analysisEngine` below — no component changes required.
 *
 * The UI reads stage state from the engine only. It never advances a stage on a
 * timer of its own, and it never invents a metric that is not in the snapshot.
 */

import { demoFixtureFor, DEMO_SOURCES, findDemoSource } from '@/demo/fixtureCaptures'
import { formatBytes, formatInt, formatProbability } from '@/lib/format'
import type {
  AnalysisRun,
  CaptureAnnotation,
  DemoSource,
  LedgerStatus,
  PipelineStageId,
  PipelineStageReport,
  PredictionResult,
  RunInput,
  StageEvidence,
} from '@/types/backend'

export type RunTarget =
  | { type: 'source'; source: DemoSource }
  | { type: 'upload'; file: File; kind: 'pcap' | 'csv' }

export interface RunSnapshot {
  run: AnalysisRun
  result: PredictionResult | null
  ledger: LedgerStatus | null
  /** Ground-truth episodes for this capture, when the repository has them. */
  annotation: CaptureAnnotation | null
}

export interface RunController {
  cancel(): void
}

/**
 * Outcome of a containment (what-if) ablation.
 *
 * `basis` states how much of the counterfactual was actually computed:
 *
 * - `engine` — the pipeline re-ran with the host's rows and flows removed
 *   (`app/panels.py :: what_if_remove_host`). Exact.
 * - `own-rows` — only the removed host's own alert rows were dropped, which is
 *   the component derivable from a finished result. Peer hosts whose window
 *   features included traffic to or from this host are NOT re-scored, so the
 *   real after-count could be lower. The UI must say so.
 */
export interface ContainmentOutcome {
  host: string
  basis: 'engine' | 'own-rows'
  beforeAlerts: number
  afterAlerts: number
  deltaAlerts: number
  beforePeak: number | null
  afterPeak: number | null
  hostAlerts: number
  note: string
}

export interface AnalysisEngine {
  /** `demo` means the numbers are fixture values, not engine output. */
  readonly kind: 'demo' | 'service'
  readonly label: string
  listSources(): DemoSource[]
  /** Can this engine analyse an operator-supplied file? */
  readonly acceptsUploads: boolean
  start(
    target: RunTarget,
    fprBudget: number,
    onSnapshot: (snapshot: RunSnapshot) => void,
  ): RunController
  containHost(result: PredictionResult, host: string): Promise<ContainmentOutcome>
}

const STAGE_ORDER: PipelineStageId[] = [
  'capture',
  'features',
  'model',
  'forecast',
  'explanation',
  'ledger',
]

/** Fixture pacing, in ms. Only affects the demo engine. */
const STAGE_DURATION_MS: Record<PipelineStageId, number> = {
  capture: 700,
  features: 1600,
  model: 1200,
  forecast: 850,
  explanation: 1150,
  ledger: 800,
}

function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
}

function pendingStages(): PipelineStageReport[] {
  return STAGE_ORDER.map((id) => ({
    id,
    state: 'pending',
    evidence: [],
    started_at: null,
    finished_at: null,
  }))
}

function runInputFor(target: RunTarget): RunInput {
  if (target.type === 'source') {
    const { source } = target
    return {
      name: source.path.split('/').pop() ?? source.path,
      bytes: source.bytes ?? 0,
      kind: source.kind,
      engine_variant: source.engine_variant,
      sha256: null,
      source: `repo:${source.path}`,
    }
  }
  return {
    name: target.file.name,
    bytes: target.file.size,
    kind: target.kind,
    engine_variant: target.kind === 'pcap' ? 'full' : 'flow',
    sha256: null,
    source: 'upload',
  }
}

function evidenceFor(
  stage: PipelineStageId,
  input: RunInput,
  fprBudget: number,
  fixture: ReturnType<typeof demoFixtureFor>,
): StageEvidence[] {
  const { result, ledger, capture } = fixture
  switch (stage) {
    case 'capture':
      return [
        { label: 'input', value: `${input.name} · ${formatBytes(input.bytes)}` },
        {
          label: 'path',
          value:
            input.kind === 'pcap'
              ? 'PCAP · full 30-feature extractor'
              : 'flow CSV · flow-only features (decision 001)',
        },
        { label: 'engine variant', value: input.engine_variant },
      ]
    case 'features':
      return [
        { label: 'flows', value: formatInt(capture.flows) },
        { label: 'host windows', value: formatInt(capture.hostWindows) },
        { label: 'named features', value: `${capture.featureCount} per window` },
      ]
    case 'model':
      return [
        { label: 'scored', value: `${formatInt(result.n_host_windows)} host-windows` },
        { label: 'window / stride', value: '15 s / 5 s' },
        { label: 'model', value: input.engine_variant === 'full' ? 'engine_model.json' : 'engine_model_flow.json' },
      ]
    case 'forecast':
      return [
        { label: 'alerts', value: formatInt(result.n_alerts) },
        { label: 'threshold', value: formatProbability(result.threshold) },
        { label: 'fpr budget', value: `${fprBudget * 100}% of host-windows` },
      ]
    case 'explanation': {
      const techniques = [...new Set(result.forecasts.map((f) => f.technique).filter(Boolean))]
      return [
        { label: 'explained alerts', value: formatInt(result.n_alerts) },
        { label: 'evidence', value: 'top-5 named features per alert' },
        { label: 'techniques', value: techniques.join(' · ') || 'none' },
      ]
    }
    case 'ledger':
      return [
        { label: 'records', value: formatInt(ledger.records ?? 0) },
        { label: 'chain', value: ledger.verified ? 'verified' : 'FAILED' },
        { label: 'checkpoint', value: ledger.anchored ? 'anchored (Merkle root)' : 'not anchored' },
      ]
    default:
      return []
  }
}

class DemoEngine implements AnalysisEngine {
  readonly kind = 'demo' as const
  readonly label = 'Demo fixture engine'
  readonly acceptsUploads = false

  listSources(): DemoSource[] {
    return DEMO_SOURCES
  }

  /**
   * Derives only what a finished result can prove: the alert rows belonging to
   * the contained host disappear. It does NOT re-score peer hosts — that needs
   * the engine — and the returned `basis` says so.
   */
  async containHost(result: PredictionResult, host: string): Promise<ContainmentOutcome> {
    await new Promise((resolve) => setTimeout(resolve, 420))

    const remaining = result.forecasts.filter((forecast) => forecast.host !== host)
    const hostAlerts = result.forecasts.length - remaining.length
    const peak = (list: typeof result.forecasts) =>
      list.length === 0 ? null : list.reduce((max, f) => Math.max(max, f.probability), 0)

    return {
      host,
      basis: 'own-rows',
      beforeAlerts: result.n_alerts,
      afterAlerts: result.n_alerts - hostAlerts,
      deltaAlerts: -hostAlerts,
      beforePeak: peak(result.forecasts),
      afterPeak: peak(remaining),
      hostAlerts,
      note: 'Ablation of this host\'s own alert rows. The full counterfactual re-runs the pipeline with the host\'s flows removed (app/panels.py :: what_if_remove_host), which also re-scores peer hosts whose window features included this host — that part needs the local engine service and is not estimated here.',
    }
  }

  start(
    target: RunTarget,
    fprBudget: number,
    onSnapshot: (snapshot: RunSnapshot) => void,
  ): RunController {
    const sourceId = target.type === 'source' ? target.source.id : 'synthetic_pcap'
    const fixture = demoFixtureFor(sourceId, fprBudget)
    const input = runInputFor(target)
    const scale = prefersReducedMotion() ? 0.28 : 1

    const run: AnalysisRun = {
      id: `demo-${Date.now().toString(36)}`,
      state: 'running',
      input,
      fpr_budget: fprBudget,
      stages: pendingStages(),
      summary: null,
      error: null,
      cancellable: true,
      notes: [
        'Fixture run: stage timings are simulated locally and the result is a demo fixture, not engine output.',
      ],
    }

    let timer: ReturnType<typeof setTimeout> | undefined
    let finished = false

    const emit = (result: PredictionResult | null, ledger: LedgerStatus | null) => {
      onSnapshot({
        run: { ...run, stages: run.stages.map((stage) => ({ ...stage })) },
        result,
        ledger,
        annotation: result ? fixture.annotation : null,
      })
    }

    const stageAt = (index: number) => run.stages[index]

    const beginStage = (index: number) => {
      const stage = stageAt(index)
      if (!stage) return
      stage.state = 'active'
      stage.started_at = Date.now() / 1000
      emit(null, null)

      timer = setTimeout(() => {
        stage.state = 'done'
        stage.finished_at = Date.now() / 1000
        stage.evidence = evidenceFor(stage.id, input, fprBudget, fixture)

        if (index + 1 < run.stages.length) {
          emit(null, null)
          beginStage(index + 1)
          return
        }

        finished = true
        run.state = 'succeeded'
        run.cancellable = false
        run.summary = {
          n_flows: fixture.result.n_flows,
          n_host_windows: fixture.result.n_host_windows,
          n_alerts: fixture.result.n_alerts,
          threshold: fixture.result.threshold,
          fpr_budget: fprBudget,
          ledger: fixture.ledger,
        }
        emit(fixture.result, fixture.ledger)
      }, STAGE_DURATION_MS[stage.id] * scale)
    }

    emit(null, null)
    beginStage(0)

    return {
      cancel: () => {
        if (finished) return
        finished = true
        if (timer) clearTimeout(timer)
        for (const stage of run.stages) {
          if (stage.state === 'active') stage.state = 'skipped'
        }
        run.state = 'cancelled'
        run.cancellable = false
        run.notes = [...run.notes, 'Run cancelled by the analyst. No result was produced.']
        emit(null, null)
      },
    }
  }
}

export const analysisEngine: AnalysisEngine = new DemoEngine()

/** True while the page is backed by fixture data instead of the real engine. */
export const ENGINE_IS_DEMO = analysisEngine.kind === 'demo'

export { findDemoSource }
