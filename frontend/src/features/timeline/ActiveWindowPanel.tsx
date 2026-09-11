import { ArrowRight, Network } from 'lucide-react'
import { Link } from 'react-router'

import type { ReplayModel, ReplaySlice } from '@/features/timeline/timelineModel'
import { formatPercent, formatWindowStart } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'

interface ActiveWindowPanelProps {
  model: ReplayModel
  slice: ReplaySlice | null
  cursor: number | null
}

/** What is true at the cursor: the alerting hosts, and where to go next. */
export function ActiveWindowPanel({ model, slice, cursor }: ActiveWindowPanelProps) {
  return (
    <section className="wx-panel" aria-labelledby="tl-active-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="tl-active-title">
          At the cursor
        </span>
        <span className="wx-mono">
          {cursor === null ? 'not scrubbed' : formatWindowStart(cursor)}
        </span>
      </div>

      <div className="wx-panel-body" style={{ display: 'grid', gap: 12 }}>
        {cursor === null && (
          <p className="wx-stage-note" style={{ margin: 0 }}>
            Press play or drag the track to move through capture time. The attack graph follows the
            same cursor.
          </p>
        )}

        {cursor !== null && (
          <>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
              {slice?.activeEpisodes.map((episode) => (
                <span
                  className="stage-badge"
                  style={{ color: stageColor(episode.stage) }}
                  key={`${episode.name}-${episode.start}`}
                >
                  <i aria-hidden="true" /> annotated · {episode.name}
                </span>
              ))}
              <span className="wx-pill wx-mono">
                {slice?.activeHosts.length ?? 0} host{slice?.activeHosts.length === 1 ? '' : 's'} alerting
              </span>
              <span className="wx-pill wx-mono">
                {slice?.seenHosts.length ?? 0} seen so far
              </span>
            </div>

            {slice && slice.activeHosts.length > 0 ? (
              <div className="replay-hosts">
                {slice.activeHosts.map((host) => (
                  <div className="replay-host" key={host.host}>
                    <div style={{ minWidth: 0 }}>
                      <div className="dash-host">{host.host}</div>
                      <div className="wx-mono" style={{ marginTop: 4, color: 'var(--c-text-muted)' }}>
                        {host.technique ? `${host.technique} · ${host.techniqueName}` : 'no technique mapped'}
                      </div>
                    </div>
                    <span className="stage-badge" style={{ color: stageColor(host.stage) }}>
                      <i aria-hidden="true" /> {stageLabel(host.stage)}
                    </span>
                    <span className="wx-num" style={{ fontWeight: 700 }}>
                      {formatPercent(host.probability, 1)}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="wx-stage-note" style={{ margin: 0 }}>
                No host-window above the threshold at this instant.
                {model.completion !== null && cursor < model.completion && model.firstAlert && cursor > model.firstAlert.time
                  ? ' This is inside the lead-time window — the warning has already been raised and the attack has not completed.'
                  : ''}
              </p>
            )}

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {slice?.activeHosts[0] && (
                <Link
                  className="wx-btn is-primary"
                  to={`/incident/${encodeURIComponent(slice.activeHosts[0].host)}`}
                >
                  Open incident · {slice.activeHosts[0].host} <ArrowRight size={14} aria-hidden="true" />
                </Link>
              )}
              <Link className="wx-btn" to="/graph">
                <Network size={14} aria-hidden="true" /> Watch it in the attack graph
              </Link>
            </div>
          </>
        )}
      </div>
    </section>
  )
}
