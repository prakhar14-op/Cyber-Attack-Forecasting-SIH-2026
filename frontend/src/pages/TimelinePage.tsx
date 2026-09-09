import { Activity } from 'lucide-react'

import { WorkspacePage } from '@/components/ui/WorkspacePage'

export default function TimelinePage() {
  return (
    <WorkspacePage
      eyebrow="Temporal evidence"
      title="See when the attack began to form."
      description="A scrub-capable timeline will compare the max host score with the validation-derived alert threshold and connect alert formation to incident evidence."
      icon={Activity}
      plannedViews={['Network score', 'Stage markers', 'Lead-time interval']}
    />
  )
}
