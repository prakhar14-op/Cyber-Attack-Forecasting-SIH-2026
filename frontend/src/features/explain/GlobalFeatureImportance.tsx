import { useReducedMotion } from 'motion/react'
import { Bar, BarChart, Cell, ResponsiveContainer, XAxis, YAxis } from 'recharts'

import { SHAP_XGB_TOP10, TOTAL_WINDOW_FEATURES } from '@/data/modelArtifacts'

/** Packet-statistic feature names — highlighted to make the PCAP argument. */
const PACKET_FEATURES = new Set([
  'ttl_mean',
  'payload_hist_0',
  'tcp_win_var',
  'tcp_win_mean',
])

export function GlobalFeatureImportance() {
  const reduceMotion = useReducedMotion()
  const data = SHAP_XGB_TOP10
  const height = Math.max(data.length * 30, 220)

  return (
    <section className="wx-panel" aria-labelledby="explain-shap-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="explain-shap-title">
          Global feature importance
        </span>
        <span className="wx-mono">mean |SHAP| · top 10 of {TOTAL_WINDOW_FEATURES}</span>
      </div>

      <div className="wx-panel-body">
        <div style={{ width: '100%', height }}>
          <ResponsiveContainer>
            <BarChart
              data={data}
              layout="vertical"
              margin={{ top: 0, right: 52, bottom: 0, left: 0 }}
              barCategoryGap={8}
            >
              <XAxis type="number" hide />
              <YAxis
                type="category"
                dataKey="feature"
                width={140}
                stroke="transparent"
                tick={{ fill: '#475569', fontSize: 11, fontFamily: 'monospace' }}
              />
              <Bar
                dataKey="meanAbsShap"
                radius={[0, 4, 4, 0]}
                isAnimationActive={!reduceMotion}
                label={{
                  position: 'right',
                  fill: '#475569',
                  fontSize: 10,
                  formatter: (value: number) => value.toFixed(3),
                }}
              >
                {data.map((entry) => (
                  <Cell
                    key={entry.feature}
                    fill={PACKET_FEATURES.has(entry.feature) ? 'var(--c-accent)' : 'var(--c-text-muted)'}
                    fillOpacity={0.85}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <p className="wx-stage-note" style={{ marginTop: 10 }}>
          Top 10 of {TOTAL_WINDOW_FEATURES} window features, ranked by mean |SHAP| over the XGBoost
          model. Packet-statistic features (highlighted) dominate the ranking — which is why a PCAP
          is preferred over a flow CSV, since a CSV cannot carry them. Source:{' '}
          <code>diagnostics/shap_xgb_top10.json</code>.
        </p>
      </div>
    </section>
  )
}
