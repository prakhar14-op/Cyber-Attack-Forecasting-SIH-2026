import { Network } from 'lucide-react'

import { WorkspacePage } from '@/components/ui/WorkspacePage'

export default function GraphPage() {
  return (
    <WorkspacePage
      eyebrow="Host topology"
      title="Trace attack structure across the network."
      description="The flagship 3D view will visualize real host nodes, flow edges and source-host risk. No graph or synthetic topology is generated in the foundation."
      icon={Network}
      plannedViews={['Host attack graph', 'Node evidence panel', 'Containment what-if']}
    />
  )
}
