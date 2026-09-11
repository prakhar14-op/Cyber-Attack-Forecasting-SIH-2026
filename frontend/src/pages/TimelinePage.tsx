import { useEffect, useMemo, useState } from 'react'

import { CaptureContextBar } from '@/features/dashboard/CaptureContextBar'
import { DashboardEmptyState } from '@/features/dashboard/DashboardEmptyState'
import { ActiveWindowPanel } from '@/features/timeline/ActiveWindowPanel'
import { LeadTimeStory } from '@/features/timeline/LeadTimeStory'
import { ReplayControls } from '@/features/timeline/ReplayControls'
import { ReplayTrack } from '@/features/timeline/ReplayTrack'
import { buildReplayModel, replaySliceAt } from '@/features/timeline/timelineModel'
import { formatSeconds } from '@/lib/format'
import { useAnalysisSession } from '@/services/analysisSessionContext'
import { useReplay } from '@/services/replayContext'

export default function TimelinePage() {
  const { session } = useAnalysisSession()
  const replay = useReplay()
  const [zoom, setZoom] = useState(1)

  const model = useMemo(
    () => (session ? buildReplayModel(session.result, session.annotation) : null),
    [session],
  )

  const slice = useMemo(
    () => (model && replay.cursor !== null ? replaySliceAt(model, replay.cursor) : null),
    [model, replay.cursor],
  )

  // Space toggles playback, arrows step one window — standard replay keys.
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      if (target && ['INPUT', 'TEXTAREA', 'BUTTON', 'SELECT'].includes(target.tagName)) return
      if (event.code === 'Space') {
        event.preventDefault()
        replay.toggle()
      } else if (event.code === 'ArrowRight') {
        event.preventDefault()
        replay.step(1)
      } else if (event.code === 'ArrowLeft') {
        event.preventDefault()
        replay.step(-1)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [replay])

  // Zoom keeps the cursor centred; at 1x the whole capture is in view.
  const view = useMemo(() => {
    if (!model) return { start: 0, end: 1 }
    const full = model.range.end - model.range.start
    const span = full / zoom
    const centre = replay.cursor ?? model.range.start + full / 2
    let start = centre - span / 2
    start = Math.max(model.range.start, Math.min(start, model.range.end - span))
    return { start, end: start + span }
  }, [model, replay.cursor, zoom])

  const header = (
    <header className="wx-header">
      <div>
        <span className="wx-mono wx-kicker">Operations / 04 · replay</span>
        <h1>Attack Timeline</h1>
        <p>
          Forensic replay of the capture: when each host crossed the alert threshold, what the
          annotated ground truth says, and how much time the warning bought. The attack graph
          follows this cursor.
        </p>
      </div>
      {model?.medianLeadSeconds !== null && model?.medianLeadSeconds !== undefined && (
        <div className="wx-header-status">
          <span className="wx-pill wx-mono tone-info">
            median lead {formatSeconds(model.medianLeadSeconds)}
          </span>
          <span className="wx-pill wx-mono">{model.leads.length} annotated episodes</span>
        </div>
      )}
    </header>
  )

  if (!session || !model) {
    return (
      <div>
        {header}
        <div style={{ marginTop: 18 }}>
          <DashboardEmptyState />
        </div>
      </div>
    )
  }

  return (
    <div>
      {header}

      <div style={{ marginTop: 16 }}>
        <CaptureContextBar session={session} />
      </div>

      <div className="replay-shell" style={{ marginTop: 12 }}>
        <div className="replay-head">
          <span className="wx-mono">Threat replay · network score per scored window</span>
          <span className="wx-mono" style={{ color: '#94a3b8' }}>
            {model.windows.length} alert windows · bracket = first alert → last completion · per-episode lead below
          </span>
        </div>

        <ReplayTrack
          model={model}
          cursor={replay.cursor}
          view={view}
          threshold={session.result.threshold}
          onSeek={replay.setCursor}
        />

        <ReplayControls
          playing={replay.playing}
          speed={replay.speed}
          cursor={replay.cursor}
          windowStart={slice?.window?.start ?? null}
          zoom={zoom}
          onToggle={replay.toggle}
          onStep={replay.step}
          onSpeed={replay.setSpeed}
          onZoom={setZoom}
          onReset={() => {
            setZoom(1)
            replay.reset()
          }}
        />
      </div>

      <div className="dash-row is-triage">
        <LeadTimeStory model={model} slice={slice} />
        <ActiveWindowPanel model={model} slice={slice} cursor={replay.cursor} />
      </div>
    </div>
  )
}
