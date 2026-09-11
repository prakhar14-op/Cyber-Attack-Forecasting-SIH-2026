import { GlobalFeatureImportance } from '@/features/explain/GlobalFeatureImportance'
import { LimitationsPanel } from '@/features/explain/LimitationsPanel'
import { MitreTechniqueMap } from '@/features/explain/MitreTechniqueMap'
import { ModelPipeline } from '@/features/explain/ModelPipeline'
import { ModelRelationship } from '@/features/explain/ModelRelationship'
import { PredictionExplanation } from '@/features/explain/PredictionExplanation'
import { StageCoverage } from '@/features/explain/StageCoverage'
import { useAnalysisSession } from '@/services/analysisSessionContext'

export default function ExplainPage() {
  const { session } = useAnalysisSession()

  return (
    <div>
      <header className="wx-header">
        <div>
          <span className="wx-mono wx-kicker">Investigation / 06 · transparency</span>
          <h1>Explainability</h1>
          <p>
            How the deployed model scores a capture, what globally drives it, why the top alert
            fired, how it maps to MITRE ATT&amp;CK, and — stated first-class — what it cannot do.
            Every figure is cited to its source in the project.
          </p>
        </div>
      </header>

      <div className="wx-stack" style={{ marginTop: 18 }}>
        <ModelPipeline />
        <GlobalFeatureImportance />
        <PredictionExplanation session={session} />
        <ModelRelationship />
        <MitreTechniqueMap session={session} />
        <StageCoverage session={session} />
        <LimitationsPanel />
      </div>
    </div>
  )
}
