import { Boxes, Clock, Info, MousePointerClick, Move3d, Pause, Play } from 'lucide-react'
import { useReducedMotion } from 'motion/react'
import { Suspense, lazy, useMemo, useState } from 'react'
import { Link } from 'react-router'

import { DashboardEmptyState } from '@/features/dashboard/DashboardEmptyState'
import { Graph2DFallback } from '@/features/graph/Graph2DFallback'
import { GraphLegend } from '@/features/graph/GraphLegend'
import { NodeInspector } from '@/features/graph/NodeInspector'
import { buildGraphModel } from '@/features/graph/graphModel'
import { buildReplayModel, replaySliceAt } from '@/features/timeline/timelineModel'
import { formatInt, formatWindowStart } from '@/lib/format'
import { stageHex } from '@/lib/stages'
import { useAnalysisSession } from '@/services/analysisSessionContext'
import { useReplay } from '@/services/replayContext'

// The whole three.js/R3F bundle is only fetched when the 3D view is actually shown.
const GraphScene = lazy(() =>
  import('@/features/graph/GraphScene').then((module) => ({ default: module.GraphScene })),
)

function webglAvailable(): boolean {
  try {
    const canvas = document.createElement('canvas')
    return Boolean(
      window.WebGLRenderingContext &&
        (canvas.getContext('webgl2') || canvas.getContext('webgl')),
    )
  } catch {
    return false
  }
}

export default function GraphPage() {
  const { session } = useAnalysisSession()
  const replay = useReplay()
  const reduceMotion = useReducedMotion() ?? false
  const supports3D = useMemo(webglAvailable, [])
  // Reduced motion starts in the static 2D rendering; the analyst can opt in.
  const [use3D, setUse3D] = useState(() => supports3D && !reduceMotion)
  const [selected, setSelected] = useState<string | null>(null)

  const result = session?.result ?? null
  const model = useMemo(() => (result ? buildGraphModel(result) : null), [result])
  const selectedNode = model?.nodes.find((node) => node.ip === selected) ?? null

  const replayModel = useMemo(
    () => (session ? buildReplayModel(session.result, session.annotation) : null),
    [session],
  )

  // Keyed on the QUANTISED cursor, so the scene re-renders once per 5 s window
  // instead of once per animation frame during playback.
  const replayFocus = useMemo(() => {
    if (!replay.engaged || !replayModel || replay.cursorWindow === null) return null
    const slice = replaySliceAt(replayModel, replay.cursorWindow)
    return {
      activeHosts: new Set(slice.activeHosts.map((host) => host.host)),
      seenHosts: new Set(slice.seenHosts),
      stageByHost: new Map(slice.activeHosts.map((host) => [host.host, stageHex(host.stage)])),
      cursorLabel: formatWindowStart(replay.cursorWindow),
      episodeNames: slice.activeEpisodes.map((episode) => episode.name),
    }
  }, [replay.cursorWindow, replay.engaged, replayModel])

  const header = (
    <header className="wx-header">
      <div>
        <span className="wx-mono wx-kicker">Investigation / 03 · structure</span>
        <h1>Attack Graph</h1>
        <p>
          The host communication graph the temporal encoder operates on. Nodes are hosts, edges are
          source→destination flow relationships, and both come straight from the analysed capture.
        </p>
      </div>
    </header>
  )

  if (!session || !result || !model) {
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

      <div className="graph-stage" style={{ marginTop: 16 }}>
        <div className="graph-overlay at-top">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            <span className="graph-chip">
              <Boxes size={12} aria-hidden="true" /> {model.shown} of {model.total} hosts
            </span>
            <span className="graph-chip" style={{ color: '#fca5a5' }}>
              <i aria-hidden="true" /> {model.counts.high} high risk
            </span>
            <span className="graph-chip" style={{ color: '#fcd34d' }}>
              <i aria-hidden="true" /> {model.counts.alerting} alerting
            </span>
            <span className="graph-chip">{formatInt(model.edges.length)} edges</span>
            {session.isFixture && <span className="graph-chip" style={{ color: '#fdba74' }}>demo fixture</span>}
          </div>

          <div style={{ display: 'flex', gap: 8 }}>
            {replayFocus ? (
              <span className="graph-chip" style={{ color: '#7dd3fc' }}>
                <Clock size={12} aria-hidden="true" /> replay {replayFocus.cursorLabel}
                {replayFocus.episodeNames.length > 0 ? ` · ${replayFocus.episodeNames.join(', ')}` : ''}
              </span>
            ) : (
              <Link className="graph-chip" to="/timeline" style={{ textDecoration: 'none' }}>
                <Clock size={12} aria-hidden="true" /> sync with timeline
              </Link>
            )}
            {replayModel && replayModel.windows.length > 0 && (
              <button
                type="button"
                className="graph-chip"
                style={{ cursor: 'pointer' }}
                onClick={replay.toggle}
                aria-pressed={replay.playing}
              >
                {replay.playing ? <Pause size={12} aria-hidden="true" /> : <Play size={12} aria-hidden="true" />}
                {replay.playing ? 'pause replay' : 'play replay'}
              </button>
            )}
            <span className="graph-chip">
              {use3D ? (
                <>
                  <Move3d size={12} aria-hidden="true" /> drag orbit · scroll zoom · right-drag pan
                </>
              ) : (
                <>
                  <MousePointerClick size={12} aria-hidden="true" /> static 2D rendering
                </>
              )}
            </span>
            {supports3D && (
              <button
                type="button"
                className="graph-chip"
                style={{ cursor: 'pointer' }}
                onClick={() => setUse3D((value) => !value)}
              >
                {use3D ? 'Switch to 2D' : 'Enable 3D view'}
              </button>
            )}
          </div>
        </div>

        {use3D ? (
          <Suspense
            fallback={
              <div style={{ display: 'grid', height: '100%', placeItems: 'center' }}>
                <span className="graph-chip">loading local 3D module…</span>
              </div>
            }
          >
            <GraphScene
              model={model}
              selected={selected}
              onSelect={setSelected}
              reduceMotion={reduceMotion}
              replay={replayFocus}
            />
          </Suspense>
        ) : (
          <Graph2DFallback
            model={model}
            selected={selected}
            onSelect={setSelected}
            replay={replayFocus}
          />
        )}

        <div className="graph-overlay at-bottom">
          <GraphLegend model={model} threshold={result.threshold} />
        </div>

        {selectedNode && (
          <NodeInspector node={selectedNode} result={result} onClose={() => setSelected(null)} />
        )}
      </div>

      {!supports3D && (
        <div className="wx-notice tone-warn" style={{ marginTop: 12 }} role="note">
          <Info size={15} aria-hidden="true" />
          <div>
            WebGL is unavailable in this browser, so the graph is rendered as a static 2D projection
            of the same layout. Every host, edge and risk band is still shown.
          </div>
        </div>
      )}

      {model.truncated && (
        <div className="wx-notice" style={{ marginTop: 12 }} role="note">
          <Info size={15} aria-hidden="true" />
          <div>
            Showing the {model.shown} highest-risk hosts of {model.total} for readability. Ranking is
            by peak probability, then alert count, then flow weight.
          </div>
        </div>
      )}
    </div>
  )
}
