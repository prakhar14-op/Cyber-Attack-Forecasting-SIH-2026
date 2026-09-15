import { ArrowRight } from 'lucide-react'

interface PipelineNode {
  label: string
  modules: string[]
  detail: string
}

/**
 * The real offline pipeline, node by node. Every module label is a real file in
 * the Python backend — this diagram documents that surface, it does not invent
 * a flow.
 */
const NODES: PipelineNode[] = [
  {
    label: 'Capture',
    modules: ['PCAP / flow CSV'],
    detail: 'Uploaded capture — packet trace or flow records.',
  },
  {
    label: 'Feature extraction',
    modules: ['data/packet_features.py', 'data/flow_features.py'],
    detail: 'Streaming extraction of packet and flow statistics.',
  },
  {
    label: 'Window features',
    modules: ['data/windows.py'],
    detail: '30 named features per (source host, 15 s window).',
  },
  {
    label: 'Engine scoring',
    modules: ['engine/predict.py', 'artifacts/engine_model*.json'],
    detail: 'XGBoost model scores each host-window.',
  },
  {
    label: 'FPR-budget threshold',
    modules: ['engine/thresholds.py'],
    detail: 'Alert cut fixed on the validation split, not tuned here.',
  },
  {
    label: 'Explain + MITRE',
    modules: ['engine/explain.py', 'engine/technique_map.yaml'],
    detail: 'TreeSHAP named-feature attribution + technique mapping.',
  },
  {
    label: 'Tamper-evident ledger',
    modules: ['ledger/ledger.py'],
    detail: 'Hash chain + Merkle roots append every forecast.',
  },
]

export function ModelPipeline() {
  return (
    <section className="wx-panel" aria-labelledby="explain-pipeline-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="explain-pipeline-title">
          Model pipeline
        </span>
        <span className="wx-mono">offline · batch · source: backend modules</span>
      </div>

      <div className="wx-panel-body">
        <ol
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'stretch',
            gap: 10,
            margin: 0,
            padding: 0,
            listStyle: 'none',
          }}
        >
          {NODES.map((node, index) => (
            <li
              key={node.label}
              style={{ display: 'flex', alignItems: 'stretch', gap: 10, minWidth: 0 }}
            >
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 6,
                  minWidth: 172,
                  maxWidth: 220,
                  border: '1px solid var(--c-line)',
                  borderRadius: 11,
                  padding: '12px 13px',
                  background: 'var(--c-surface)',
                }}
              >
                <span className="wx-mono wx-kicker" style={{ fontSize: 9 }}>
                  {String(index + 1).padStart(2, '0')}
                </span>
                <span style={{ fontSize: 13, fontWeight: 700, lineHeight: 1.2 }}>{node.label}</span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                  {node.modules.map((module) => (
                    <code
                      key={module}
                      className="wx-mono"
                      style={{ fontSize: 10.5, color: 'var(--c-accent)', wordBreak: 'break-all' }}
                    >
                      {module}
                    </code>
                  ))}
                </div>
                <p
                  style={{
                    margin: '2px 0 0',
                    fontSize: 11,
                    lineHeight: 1.5,
                    color: 'var(--c-text-muted)',
                  }}
                >
                  {node.detail}
                </p>
              </div>
              {index < NODES.length - 1 && (
                <span
                  aria-hidden="true"
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    color: 'var(--c-text-muted)',
                  }}
                >
                  <ArrowRight size={16} strokeWidth={1.8} />
                </span>
              )}
            </li>
          ))}
        </ol>

        <p className="wx-stage-note" style={{ marginTop: 12 }}>
          The deployed app scores with the XGBoost engine model (CPU-cheap, natively
          TreeSHAP-explainable). Every stage above is a real module in the Python backend; the
          frontend renders their output and adds no ML logic.
        </p>
      </div>
    </section>
  )
}
