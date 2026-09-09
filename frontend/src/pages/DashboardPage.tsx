import { Gauge } from 'lucide-react'

import { WorkspacePage } from '@/components/ui/WorkspacePage'

export default function DashboardPage() {
  return (
    <WorkspacePage
      eyebrow="SOC overview"
      title="Triage the network at a glance."
      description="This view will prioritize alert volume, host risk, the network-level threat timeline and the operating point using only real analysis output."
      icon={Gauge}
      plannedViews={['Threat posture', 'Forecast timeline', 'Hosts to triage']}
    />
  )
}
