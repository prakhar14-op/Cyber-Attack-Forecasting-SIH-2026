import { Info } from 'lucide-react'

import type { ReplayModel, ReplaySlice } from '@/features/timeline/timelineModel'
import { formatSeconds, formatWindowStart } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'

interface LeadTimeStoryProps {
  model: ReplayModel
  slice: ReplaySlice | null
}

/**
 * The early-warning claim, told with the only timing evidence that exists:
 * result-derived first alert and contributing windows, plus the annotated
 * completion. When there is no annotation, the last two beats say so.
 */
export function LeadTimeStory({ model, slice }: LeadTimeStoryProps) {
  const first = model.firstAlert
  const phase = slice?.phase ?? null

  return (
    <section className="wx-panel" aria-labelledby="tl-story-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="tl-story-title">
          Early-warning story
        </span>
        <span className="wx-mono">
          {model.annotationSource ? `ground truth · ${model.annotationSource}` : 'no annotation for this capture'}
        </span>
      </div>

      <div className="wx-panel-body" style={{ display: 'grid', gap: 12 }}>
        <div className="story-row">
          <div className={`story-beat${phase === 'before-first-alert' ? ' is-lead' : ''}`}>
            <h4>01 · normal</h4>
            <div className="story-value">
              {first ? formatWindowStart(model.range.start) : '—'}
            </div>
            <small>
              Capture opens. No host-window is above the threshold yet, so the result contains no
              rows for this span.
            </small>
          </div>

          <div className="story-beat">
            <h4>02 · evidence forming</h4>
            <div className="story-value">
              {model.earliestEvidence && model.earliestEvidence.secondsBeforeFirstAlert > 0
                ? formatWindowStart(model.earliestEvidence.time)
                : 'n/a'}
            </div>
            <small>
              {!model.earliestEvidence
                ? 'The first alert cites no contributing window.'
                : model.earliestEvidence.secondsBeforeFirstAlert > 0
                  ? `Oldest contributing window of the first alert — ${formatSeconds(
                      model.earliestEvidence.secondsBeforeFirstAlert,
                    )} before it fired.`
                  : 'The first alert cites only its own window: it is the earliest scored window in this capture, so no earlier evidence exists to show.'}
            </small>
          </div>

          <div className={`story-beat is-alert${phase === 'alerting' ? ' is-lead' : ''}`}>
            <h4>03 · first alert</h4>
            <div className="story-value" style={{ color: 'var(--c-danger)' }}>
              {first ? formatWindowStart(first.time) : 'none'}
            </div>
            <small>
              {first ? (
                <>
                  {first.host} at {(first.probability * 100).toFixed(1)}% ·{' '}
                  <span style={{ color: stageColor(first.stage) }}>{stageLabel(first.stage)}</span>
                </>
              ) : (
                'No host crossed the threshold in this capture.'
              )}
            </small>
          </div>

          <div className={`story-beat is-lead${phase === 'lead-window' ? ' is-alert' : ''}`}>
            <h4>04 · lead time</h4>
            <div className="story-value" style={{ color: 'var(--c-accent)' }}>
              {model.medianLeadSeconds === null ? 'n/a' : formatSeconds(model.medianLeadSeconds)}
            </div>
            <small>
              {model.medianLeadSeconds === null
                ? 'Needs an annotated completion time; this capture has none.'
                : `Median across ${model.leads.length} annotated episode${
                    model.leads.length === 1 ? '' : 's'
                  }, measured on each episode's attacking host.`}
            </small>
          </div>

          <div className={`story-beat${phase === 'after-completion' ? ' is-done' : ''}`}>
            <h4>05 · attack completion</h4>
            <div className="story-value">
              {model.completion === null ? 'n/a' : formatWindowStart(model.completion)}
            </div>
            <small>
              {model.completion === null
                ? 'No annotated episode end for this capture.'
                : 'Annotated end of the last attack episode — the deadline the alert had to beat.'}
            </small>
          </div>
        </div>

        {model.leads.length > 0 && (
          <div>
            <div className="wx-mono" style={{ marginBottom: 7, color: 'var(--c-text-muted)' }}>
              Per-episode lead
            </div>
            <table className="dash-table">
              <thead>
                <tr>
                  <th scope="col">Episode</th>
                  <th scope="col">Attacking host</th>
                  <th scope="col">First alert</th>
                  <th scope="col">Completion</th>
                  <th scope="col">Lead</th>
                </tr>
              </thead>
              <tbody>
                {model.leads.map((lead) => (
                  <tr key={lead.episode} style={{ cursor: 'default' }}>
                    <td>
                      <span className="stage-badge" style={{ color: stageColor(lead.stage) }}>
                        <i aria-hidden="true" /> {lead.episode}
                      </span>
                    </td>
                    <td className="dash-host">{lead.attacker}</td>
                    <td>{formatWindowStart(lead.firstAlert)}</td>
                    <td>{formatWindowStart(lead.completion)}</td>
                    <td style={{ color: 'var(--c-accent)', fontWeight: 700 }}>
                      {formatSeconds(lead.leadSeconds)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {model.missedEpisodes.length > 0 && (
          <div className="wx-notice tone-warn" role="note">
            <Info size={15} aria-hidden="true" />
            <div>
              {model.missedEpisodes.length} annotated episode
              {model.missedEpisodes.length === 1 ? '' : 's'} had no alert on the attacking host
              before completion ({model.missedEpisodes.map((episode) => episode.name).join(', ')}) —
              counted as a miss, not dropped.
            </div>
          </div>
        )}

        <div className="wx-notice" role="note">
          <Info size={15} aria-hidden="true" />
          <div>
            Lead time follows the project definition: annotated completion minus the first alert on
            that episode's attacking host, at the run's FPR budget. The score track shows only
            windows the engine actually returned — at or above the threshold — so an empty stretch
            means "no alert", not "no traffic". Forward ranking for t+1…t+8 is an eval-side
            capability and is not part of this result.
          </div>
        </div>
      </div>
    </section>
  )
}
