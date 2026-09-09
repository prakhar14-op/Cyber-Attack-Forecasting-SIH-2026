import { Radar } from 'lucide-react'

import { WorkspacePage } from '@/components/ui/WorkspacePage'

export default function ForecastPage() {
  return (
    <WorkspacePage
      eyebrow="Forward risk"
      title="Inspect ranking across the forecast horizon."
      description="The forecasting workspace will report the measured k-step capability honestly, including the fixed-budget operating-point limitation."
      icon={Radar}
      plannedViews={['Horizon selector', 'AUROC curve', 'Lead-time disclosure']}
    />
  )
}
