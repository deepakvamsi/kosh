import { Component, ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

type Props = { children: ReactNode }
type State = { error: Error | null }

// ErrorBoundary stops a render-time exception in any view from unmounting the whole app
// (which shows as a "complete blank screen"). Instead it shows the error and a way to
// recover, and logs details to the console for diagnosis.
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: unknown) {
    console.error('Kosh render error:', error, info)
  }

  reset = () => this.setState({ error: null })

  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="flex h-full flex-1 flex-col items-center justify-center gap-4 p-6 text-center">
        <AlertTriangle className="h-10 w-10 text-[rgb(var(--warn))]" />
        <div>
          <p className="text-sm font-medium text-[rgb(var(--text))]">Something went wrong rendering this screen</p>
          <p className="mt-1 max-w-md text-xs text-[rgb(var(--text-muted))]">
            Your vault is safe — this is only a display error. Details are in the console.
          </p>
          <p className="mt-2 max-w-md break-words font-mono text-[11px] text-[rgb(var(--text-muted))]">{this.state.error.message}</p>
        </div>
        <button onClick={this.reset}
          className="rounded-lg bg-[rgb(var(--accent))] px-4 py-2 text-sm font-medium text-white hover:bg-[rgb(var(--accent-hover))]">
          Try again
        </button>
      </div>
    )
  }
}
