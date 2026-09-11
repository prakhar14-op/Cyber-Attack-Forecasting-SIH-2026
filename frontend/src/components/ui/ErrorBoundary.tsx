import { AlertTriangle, RotateCcw } from 'lucide-react'
import { Component } from 'react'
import type { ErrorInfo, ReactNode } from 'react'

interface Props {
  children: ReactNode
}

interface State {
  error: Error | null
}

/**
 * Keeps a render failure inside one route instead of blanking the console.
 * Shows the real error text — an analyst debugging a demo needs the message,
 * not a shrug.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Local console only — there is no telemetry endpoint by design.
    console.error('route render failed', error, info.componentStack)
  }

  render() {
    const { error } = this.state
    if (!error) return this.props.children

    return (
      <div className="wx-panel" style={{ padding: 22 }}>
        <div className="wx-notice tone-danger" role="alert">
          <AlertTriangle size={15} aria-hidden="true" />
          <div>
            <strong className="wx-mono" style={{ display: 'block', marginBottom: 4 }}>
              This view failed to render
            </strong>
            {error.message}
          </div>
        </div>
        <button
          type="button"
          className="wx-btn"
          style={{ marginTop: 12 }}
          onClick={() => this.setState({ error: null })}
        >
          <RotateCcw size={14} aria-hidden="true" /> Retry view
        </button>
      </div>
    )
  }
}
