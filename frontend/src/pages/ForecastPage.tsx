import { HorizonAurocChart } from '@/features/forecast/HorizonAurocChart'
import { HorizonSummaryTable } from '@/features/forecast/HorizonSummaryTable'
import { InterpretationPanel } from '@/features/forecast/InterpretationPanel'
import { OperatingPointReality } from '@/features/forecast/OperatingPointReality'

/**
 * /forecast — page 07. Presents the k-step head honestly as a RANKING
 * capability, clearly separated from the production operating point. Reads
 * committed project results only; works with no analysis session loaded.
 */
export default function ForecastPage() {
  return (
    <div>
      <header className="wx-header">
        <div>
          <span className="wx-mono wx-kicker">Investigation / 07 · forecasting</span>
          <h1>Forecast Horizons</h1>
          <p>
            The k-step head is a verified <strong>ranking</strong> capability evaluated across
            t+1…t+12 windows (up to 60 s ahead). It is reported here separately from the shipped
            operating point — the horizon-0 fused model produces the actual early warning, not the
            k-step head.
          </p>
        </div>
      </header>

      <div className="wx-columns">
        <HorizonAurocChart />
        <OperatingPointReality />
      </div>

      <div style={{ marginTop: 14 }}>
        <HorizonSummaryTable />
      </div>

      <div style={{ marginTop: 14 }}>
        <InterpretationPanel />
      </div>
    </div>
  )
}
