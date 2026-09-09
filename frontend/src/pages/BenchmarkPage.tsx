import { ChartNoAxesCombined } from 'lucide-react'

import { WorkspacePage } from '@/components/ui/WorkspacePage'

export default function BenchmarkPage() {
  return (
    <WorkspacePage
      eyebrow="Measured performance"
      title="Keep claims tied to reproducible results."
      description="The evaluation view will render generated ablation and horizon results together with the dataset and confidence limitations that qualify them."
      icon={ChartNoAxesCombined}
      plannedViews={['Model comparison', 'Forecast horizons', 'Limitations and confidence']}
    />
  )
}
