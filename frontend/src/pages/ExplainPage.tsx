import { Binary } from 'lucide-react'

import { WorkspacePage } from '@/components/ui/WorkspacePage'

export default function ExplainPage() {
  return (
    <WorkspacePage
      eyebrow="Model evidence"
      title="Make every alert defensible."
      description="The explainability view will expose real named-feature attribution, technique mapping and model limitations without presenting embedding dimensions as evidence."
      icon={Binary}
      plannedViews={['SHAP contributions', 'Technique evidence', 'Coverage limitations']}
    />
  )
}
