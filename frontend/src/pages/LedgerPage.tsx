import { ScrollText } from 'lucide-react'

import { WorkspacePage } from '@/components/ui/WorkspacePage'

export default function LedgerPage() {
  return (
    <WorkspacePage
      eyebrow="Audit integrity"
      title="Verify every forecast offline."
      description="The ledger workspace will present hash-chain status, Merkle anchoring and exact tamper detection through the existing Python verifier."
      icon={ScrollText}
      plannedViews={['Chain status', 'Checkpoint proof', 'Tamper verification']}
    />
  )
}
