import { formatInt } from '@/lib/format'
import type { FlaggedFlow } from '@/types/backend'

/** IANA numbers the extractor records; anything else is shown as the number. */
const PROTOCOL_NAME: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' }

function microsToText(durationUs: number): string {
  if (durationUs === 0) return '0 µs'
  if (durationUs < 1000) return `${Math.round(durationUs)} µs`
  if (durationUs < 1_000_000) return `${(durationUs / 1000).toFixed(1)} ms`
  return `${(durationUs / 1_000_000).toFixed(2)} s`
}

export function FlaggedFlows({ flows }: { flows: FlaggedFlow[] }) {
  return (
    <section className="wx-panel" aria-labelledby="incident-flows-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="incident-flows-title">
          Flagged flows
        </span>
        <span className="wx-mono">
          {formatInt(flows.length)} flow{flows.length === 1 ? '' : 's'} inside the alert window
        </span>
      </div>

      <div className="wx-panel-body is-tight" style={{ paddingInline: 4 }}>
        {flows.length === 0 ? (
          <p className="wx-stage-note" style={{ margin: '8px 12px' }}>
            The engine attached no flow records to this alert.
          </p>
        ) : (
          <table className="dash-table">
            <thead>
              <tr>
                <th scope="col">Destination port</th>
                <th scope="col">Protocol</th>
                <th scope="col">Bytes</th>
                <th scope="col">SYN</th>
                <th scope="col">Duration</th>
              </tr>
            </thead>
            <tbody>
              {flows.map((flow, index) => (
                <tr key={`${flow.dst_port}-${flow.duration_us}-${index}`} style={{ cursor: 'default' }}>
                  <td className="dash-host">{flow.dst_port}</td>
                  <td>
                    {PROTOCOL_NAME[flow.protocol] ?? `proto ${flow.protocol}`}
                    <span className="wx-mono" style={{ marginLeft: 6, color: 'var(--c-text-muted)' }}>
                      {flow.protocol}
                    </span>
                  </td>
                  <td>{formatInt(flow.bytes)}</td>
                  <td>{flow.syn}</td>
                  <td>{microsToText(flow.duration_us)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}
