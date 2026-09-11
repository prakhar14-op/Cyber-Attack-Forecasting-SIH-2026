import { AblationFindings } from '@/features/benchmark/AblationFindings'
import { AurocBarChart } from '@/features/benchmark/AurocBarChart'
import { EvidencePanel } from '@/features/benchmark/EvidencePanel'
import { LimitationsPanel } from '@/features/benchmark/LimitationsPanel'
import { ModelComparisonTable } from '@/features/benchmark/ModelComparisonTable'
import { OperatingPointPanel } from '@/features/benchmark/OperatingPointPanel'

/**
 * /benchmark — page 09. An evidence console for judges. Reads committed
 * project results only; works with no analysis session loaded.
 */
export default function BenchmarkPage() {
  return (
    <div>
      <header className="wx-header">
        <div>
          <span className="wx-mono wx-kicker">Investigation / 09 · evidence</span>
          <h1>Benchmark &amp; Evidence</h1>
          <p>
            Reproducible model comparison, ablation and thresholding evidence — every number traces
            back through eval/ablation.py to results/*.json, with the confidence limitations that
            qualify them stated as first-class content.
          </p>
        </div>
      </header>

      <div style={{ marginTop: 16 }}>
        <ModelComparisonTable />
      </div>

      <div className="wx-columns">
        <AurocBarChart />
        <AblationFindings />
      </div>

      <div className="wx-columns">
        <OperatingPointPanel />
        <EvidencePanel />
      </div>

      <div style={{ marginTop: 14 }}>
        <LimitationsPanel />
      </div>
    </div>
  )
}
