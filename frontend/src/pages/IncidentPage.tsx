import { FileSearch } from 'lucide-react'
import { useParams } from 'react-router'

import { WorkspacePage } from '@/components/ui/WorkspacePage'

export default function IncidentPage() {
  const { host } = useParams<{ host: string }>()
  const context = host && host !== 'host-preview' ? ` Route context: ${host}.` : ''

  return (
    <WorkspacePage
      eyebrow="Incident investigation"
      title="Explain why this host was flagged."
      description={`This workspace will join probability, ATT&CK stage, named SHAP features, contributing windows and flagged flows for the selected host.${context}`}
      icon={FileSearch}
      plannedViews={['Named-feature evidence', 'Contributing windows', 'Flagged flows']}
    />
  )
}
