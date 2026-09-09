import { ScanSearch } from 'lucide-react'

import { WorkspacePage } from '@/components/ui/WorkspacePage'

export default function AnalyzePage() {
  return (
    <WorkspacePage
      eyebrow="Capture ingestion"
      title="Begin with network evidence."
      description="The file-first analysis workspace will accept PCAP or flow CSV inputs and run the existing offline Python pipeline. Backend integration is intentionally deferred."
      icon={ScanSearch}
      plannedViews={['Secure file drop', 'Pipeline progress', 'Input capability notes']}
    />
  )
}
