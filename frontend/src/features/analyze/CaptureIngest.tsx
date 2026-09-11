import { AlertTriangle, FolderOpen, Inbox, X } from 'lucide-react'
import { useRef, useState } from 'react'

import { ACCEPTED_EXTENSIONS } from '@/features/analyze/validateCapture'
import type { SelectedInput } from '@/hooks/useAnalysisRun'
import { formatBytes } from '@/lib/format'

interface CaptureIngestProps {
  input: SelectedInput | null
  validationError: string | null
  disabled: boolean
  /** Renders the ambient sweep only while a run is in flight. */
  scanning: boolean
  onFile: (file: File) => void
  onClear: () => void
}

export function CaptureIngest({
  input,
  validationError,
  disabled,
  scanning,
  onFile,
  onClear,
}: CaptureIngestProps) {
  const [dragging, setDragging] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  const takeFirst = (files: FileList | null) => {
    const file = files?.[0]
    if (file) onFile(file)
  }

  return (
    <section className="wx-panel" aria-labelledby="wx-ingest-title">
      <div className="wx-panel-head">
        <span className="wx-mono" id="wx-ingest-title">
          Capture intake
        </span>
        <span className="wx-mono">{ACCEPTED_EXTENSIONS.join(' · ')}</span>
      </div>

      <div className="wx-panel-body wx-gridfield">
        {scanning && <span className="wx-scan" aria-hidden="true" />}
        <div
          className={dragging ? 'wx-drop is-over' : 'wx-drop'}
          onDragOver={(event) => {
            event.preventDefault()
            if (!disabled) setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault()
            setDragging(false)
            if (!disabled) takeFirst(event.dataTransfer.files)
          }}
        >
          <div>
            <div className="wx-drop-icon" aria-hidden="true">
              <Inbox size={20} strokeWidth={1.8} />
            </div>
            <h3>Drop a capture to analyse</h3>
            <p>
              Packet captures take the full 30-feature path. A flow CSV runs the flow-only model —
              a CSV physically cannot carry packet statistics (decision 001).
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 16 }}>
              <button
                type="button"
                className="wx-btn"
                disabled={disabled}
                onClick={() => fileInput.current?.click()}
              >
                <FolderOpen size={14} aria-hidden="true" /> Browse file
              </button>
              {input && (
                <button type="button" className="wx-btn" disabled={disabled} onClick={onClear}>
                  <X size={14} aria-hidden="true" /> Clear
                </button>
              )}
            </div>
            <input
              ref={fileInput}
              type="file"
              accept={ACCEPTED_EXTENSIONS.join(',')}
              hidden
              onChange={(event) => {
                takeFirst(event.target.files)
                event.target.value = ''
              }}
            />
          </div>
        </div>
      </div>

      {validationError && (
        <div className="wx-panel-body is-tight" style={{ paddingTop: 0 }}>
          <div className="wx-notice tone-danger" role="alert">
            <AlertTriangle size={15} aria-hidden="true" />
            <div>{validationError}</div>
          </div>
        </div>
      )}

      {input && (
        <div className="wx-panel-body is-tight" style={{ borderTop: '1px solid var(--c-line)' }}>
          <dl style={{ margin: 0 }}>
            <div className="wx-kv wx-mono">
              <dt>Selected</dt>
              <dd>{input.label}</dd>
            </div>
            <div className="wx-kv wx-mono">
              <dt>Origin</dt>
              <dd>{input.detail}</dd>
            </div>
            <div className="wx-kv wx-mono">
              <dt>Size</dt>
              <dd className="wx-num">{formatBytes(input.bytes)}</dd>
            </div>
            <div className="wx-kv wx-mono">
              <dt>Feature path</dt>
              <dd>{input.kind === 'pcap' ? 'full · 30 features' : 'flow-only'}</dd>
            </div>
          </dl>
        </div>
      )}
    </section>
  )
}
