import { motion, useReducedMotion } from 'motion/react'
import { ArrowRight, Link as LinkIcon, ShieldAlert, ShieldCheck } from 'lucide-react'

import type { ChainEntry } from '@/lib/ledgerChain'
import { formatProbability } from '@/lib/format'
import { stageColor, stageLabel } from '@/lib/stages'
import type { AttackStage } from '@/types/backend'

interface LedgerChainViewProps {
  entries: ChainEntry[]
  /** First inconsistent index from the real verify(), or null. */
  firstBadIndex: number | null
  selectedIndex: number
  onSelect: (index: number) => void
}

function shortHash(hex: string): string {
  return hex.slice(0, 10)
}

/**
 * Horizontal, scrollable chain of blocks. Blocks before the first inconsistent
 * index render calm; the broken block and everything after it are marked
 * broken. The break state and the index come from the real verify() — nothing
 * here decides integrity on its own.
 */
export function LedgerChainView({
  entries,
  firstBadIndex,
  selectedIndex,
  onSelect,
}: LedgerChainViewProps) {
  const reduceMotion = useReducedMotion()

  return (
    <section className="wx-panel" aria-labelledby="ledger-chain-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="ledger-chain-title">
          Hash chain
        </span>
        <span className="wx-mono">
          {firstBadIndex === null
            ? `${entries.length} blocks · genesis → head`
            : `break at block ${firstBadIndex}`}
        </span>
      </div>

      <div className="wx-panel-body" style={{ overflowX: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'stretch', gap: 0, minWidth: 'min-content' }}>
          {entries.map((entry, index) => {
            const broken = firstBadIndex !== null && index >= firstBadIndex
            const isBreakPoint = firstBadIndex === index
            const selected = index === selectedIndex
            const stage = entry.stage as AttackStage
            const borderColor = broken
              ? 'var(--c-danger)'
              : selected
                ? 'var(--c-accent)'
                : 'var(--c-line)'

            return (
              <div key={entry.hash + index} style={{ display: 'flex', alignItems: 'center' }}>
                {index > 0 && (
                  <span
                    aria-hidden="true"
                    style={{
                      color: broken ? 'var(--c-danger)' : 'var(--c-text-muted)',
                      margin: '0 6px',
                      flex: '0 0 auto',
                    }}
                  >
                    <ArrowRight size={16} />
                  </span>
                )}

                <motion.button
                  type="button"
                  onClick={() => onSelect(index)}
                  aria-pressed={selected}
                  aria-label={`Block ${index}, ${broken ? 'broken' : 'verified'}`}
                  animate={
                    isBreakPoint && !reduceMotion
                      ? { x: [0, -3, 3, -2, 2, 0] }
                      : { x: 0 }
                  }
                  transition={{ duration: 0.42, ease: 'easeInOut' }}
                  style={{
                    display: 'grid',
                    gap: 6,
                    width: 176,
                    flex: '0 0 auto',
                    textAlign: 'left',
                    border: `1px solid ${borderColor}`,
                    borderRadius: 11,
                    padding: 12,
                    cursor: 'pointer',
                    background: broken
                      ? 'rgba(220, 38, 38, 0.04)'
                      : selected
                        ? 'var(--c-accent-soft)'
                        : 'var(--c-panel)',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <span className="wx-mono" style={{ color: 'var(--c-text-muted)' }}>
                      #{String(index).padStart(2, '0')} · seq {entry.seq}
                    </span>
                    {broken ? (
                      <ShieldAlert size={14} color="var(--c-danger)" aria-hidden="true" />
                    ) : (
                      <ShieldCheck size={14} color="var(--c-success)" aria-hidden="true" />
                    )}
                  </div>

                  <div
                    className="wx-mono wx-num"
                    style={{ fontSize: 12, fontWeight: 700, color: 'var(--c-text)' }}
                    title={entry.hash}
                  >
                    {shortHash(entry.hash)}
                  </div>

                  <div
                    className="wx-mono"
                    style={{ fontSize: 10.5, color: 'var(--c-text-muted)' }}
                    title={`prev ${entry.prev}`}
                  >
                    <LinkIcon size={9} aria-hidden="true" /> {entry.prev.slice(0, 8)}
                  </div>

                  <div className="dash-host" style={{ fontSize: 11 }} title={`pseudonym ${entry.host}`}>
                    {entry.host}
                  </div>

                  <div
                    className="stage-badge"
                    style={{ color: stageColor(stage), fontSize: 11 }}
                  >
                    <i aria-hidden="true" /> {stageLabel(stage)}
                  </div>

                  <div
                    className="wx-mono wx-num"
                    style={{ fontSize: 10.5, color: 'var(--c-text-muted)' }}
                  >
                    p={formatProbability(entry.probability)}
                  </div>

                  {isBreakPoint && (
                    <span className="wx-pill wx-mono tone-danger" style={{ marginTop: 2 }}>
                      <i aria-hidden="true" /> break here
                    </span>
                  )}
                </motion.button>
              </div>
            )
          })}
        </div>

        <p className="wx-stage-note" style={{ marginTop: 12 }}>
          Each block hashes its own content plus the previous block&apos;s hash. A verified block is
          calm; the first inconsistent block and everything after it are marked broken. Arrows are
          the prev-links. Select a block to target it in the tamper demo.
        </p>
      </div>
    </section>
  )
}
