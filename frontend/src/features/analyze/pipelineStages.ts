import { Braces, FileInput, Fingerprint, Radar, ScrollText, Waypoints } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

import type { PipelineStageId } from '@/types/backend'

export interface PipelineStageSpec {
  id: PipelineStageId
  index: string
  label: string
  /** What this stage does, in the pipeline's own vocabulary. */
  note: string
  /** The backend module responsible — so the stage is traceable, not decorative. */
  module: string
  icon: LucideIcon
}

export const PIPELINE_STAGES: PipelineStageSpec[] = [
  {
    id: 'capture',
    index: '01',
    label: 'CAPTURE',
    note: 'Input read · format selects the feature path',
    module: 'data/packet_features.py · data/flow_features.py',
    icon: FileInput,
  },
  {
    id: 'features',
    index: '02',
    label: 'FEATURES',
    note: 'Window-bounded named features per (source host, 15 s window)',
    module: 'data/windows.py',
    icon: Braces,
  },
  {
    id: 'model',
    index: '03',
    label: 'TEMPORAL MODEL',
    note: 'Host-window scoring on the deployed engine model · TGN encoder stays eval-side',
    module: 'engine/predict.py · artifacts/engine_model*.json',
    icon: Waypoints,
  },
  {
    id: 'forecast',
    index: '04',
    label: 'FORECAST',
    note: 'Validation-derived FPR-budget threshold decides the alerts',
    module: 'engine/thresholds.py',
    icon: Radar,
  },
  {
    id: 'explanation',
    index: '05',
    label: 'EXPLANATION',
    note: 'Named-feature SHAP, contributing windows, MITRE technique',
    module: 'engine/explain.py · engine/technique_map.yaml',
    icon: Fingerprint,
  },
  {
    id: 'ledger',
    index: '06',
    label: 'LEDGER',
    note: 'Hash-chained records, Merkle checkpoint, offline verification',
    module: 'ledger/ledger.py',
    icon: ScrollText,
  },
]

export function stageSpec(id: PipelineStageId): PipelineStageSpec {
  const found = PIPELINE_STAGES.find((stage) => stage.id === id)
  if (!found) throw new Error(`unknown pipeline stage: ${id}`)
  return found
}
