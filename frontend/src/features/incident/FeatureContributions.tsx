import { motion, useReducedMotion } from 'motion/react'

import type { TopFeature } from '@/types/backend'

/**
 * Signed SHAP contributions as a 2D diverging bar chart: right of the axis
 * pushes risk up, left pulls it down. Feature names are printed verbatim as the
 * engine reported them — real window features, never embedding indices.
 */
export function FeatureContributions({ features }: { features: TopFeature[] }) {
  const reduceMotion = useReducedMotion()
  const max = features.reduce((peak, feature) => Math.max(peak, Math.abs(feature.contribution)), 0)

  return (
    <section className="wx-panel" aria-labelledby="incident-why-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="incident-why-title">
          Why did the model fire?
        </span>
        <span className="wx-mono">TreeSHAP · named window features</span>
      </div>

      <div className="wx-panel-body">
        {features.length === 0 ? (
          <p className="wx-stage-note" style={{ margin: 0 }}>
            This alert carries no feature attribution.
          </p>
        ) : (
          <div style={{ display: 'grid', gap: 10 }}>
            {features.map((feature, index) => {
              const share = max === 0 ? 0 : Math.abs(feature.contribution) / max
              const positive = feature.contribution >= 0
              return (
                <div key={feature.feature}>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'baseline',
                      justifyContent: 'space-between',
                      gap: 12,
                      marginBottom: 5,
                    }}
                  >
                    <span
                      className="wx-mono"
                      style={{ color: 'var(--c-text)', fontSize: 11, textTransform: 'none', letterSpacing: 0 }}
                    >
                      {feature.feature}
                    </span>
                    <span className="wx-mono wx-num" style={{ color: 'var(--c-text-muted)' }}>
                      value {feature.value}
                      {'  '}
                      <b style={{ color: positive ? 'var(--c-danger)' : 'var(--c-accent)' }}>
                        {positive ? '+' : ''}
                        {feature.contribution}
                      </b>
                    </span>
                  </div>

                  {/* diverging axis: centre = zero contribution */}
                  <div
                    style={{
                      position: 'relative',
                      height: 12,
                      borderRadius: 3,
                      background: 'var(--chart-grid)',
                    }}
                  >
                    <span
                      style={{
                        position: 'absolute',
                        top: -2,
                        bottom: -2,
                        left: '50%',
                        width: 1,
                        background: 'var(--c-line)',
                      }}
                      aria-hidden="true"
                    />
                    <motion.span
                      initial={reduceMotion ? false : { scaleX: 0 }}
                      animate={{ scaleX: 1 }}
                      transition={{ duration: 0.4, delay: index * 0.04 }}
                      style={{
                        position: 'absolute',
                        top: 0,
                        bottom: 0,
                        left: positive ? '50%' : `${50 - share * 50}%`,
                        width: `${share * 50}%`,
                        transformOrigin: positive ? 'left' : 'right',
                        borderRadius: 3,
                        background: positive ? 'var(--c-danger)' : 'var(--c-accent)',
                        opacity: 0.85,
                      }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        )}

        <div
          style={{
            display: 'flex',
            gap: 14,
            marginTop: 14,
            paddingTop: 10,
            borderTop: '1px solid var(--c-line)',
          }}
        >
          <span className="wx-mono" style={{ color: 'var(--c-danger)' }}>
            → risk-increasing
          </span>
          <span className="wx-mono" style={{ color: 'var(--c-accent)' }}>
            ← risk-reducing
          </span>
        </div>
      </div>
    </section>
  )
}
