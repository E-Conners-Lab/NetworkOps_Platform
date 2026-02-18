import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

/**
 * Error Boundary component that catches JavaScript errors in child components.
 * Prevents the entire app from crashing when a component throws an error.
 */
class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    this.setState({ errorInfo });
    // Log error to console (could send to monitoring service)
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  handleReset = (): void => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  render(): ReactNode {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return <ErrorFallback error={this.state.error} onReset={this.handleReset} />;
    }

    return this.props.children;
  }
}

interface ErrorFallbackProps {
  error: Error | null;
  onReset: () => void;
}

/**
 * Default fallback UI shown when an error occurs.
 */
function ErrorFallback({ error, onReset }: ErrorFallbackProps): React.ReactElement {
  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h2 style={styles.title}>Something went wrong</h2>
        <p style={styles.message}>
          The dashboard encountered an error. This has been logged.
        </p>
        {error && (
          <details style={styles.details}>
            <summary style={styles.summary}>Error details</summary>
            <pre style={styles.pre}>{error.message}</pre>
          </details>
        )}
        <div style={styles.actions}>
          <button style={styles.button} onClick={onReset}>
            Try Again
          </button>
          <button
            style={{ ...styles.button, ...styles.secondaryButton }}
            onClick={() => window.location.reload()}
          >
            Reload Page
          </button>
        </div>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '100vh',
    backgroundColor: '#1a1a2e',
    padding: '20px',
  },
  card: {
    backgroundColor: '#16213e',
    borderRadius: '8px',
    padding: '32px',
    maxWidth: '500px',
    width: '100%',
    boxShadow: '0 4px 6px rgba(0, 0, 0, 0.3)',
    border: '1px solid #e94560',
  },
  title: {
    color: '#e94560',
    fontSize: '24px',
    marginTop: 0,
    marginBottom: '16px',
  },
  message: {
    color: '#a0a0a0',
    fontSize: '14px',
    lineHeight: 1.6,
    marginBottom: '20px',
  },
  details: {
    marginBottom: '20px',
  },
  summary: {
    color: '#808080',
    cursor: 'pointer',
    fontSize: '12px',
    marginBottom: '8px',
  },
  pre: {
    backgroundColor: '#0f0f23',
    color: '#ff6b6b',
    padding: '12px',
    borderRadius: '4px',
    fontSize: '12px',
    overflow: 'auto',
    maxHeight: '150px',
  },
  actions: {
    display: 'flex',
    gap: '12px',
  },
  button: {
    backgroundColor: '#e94560',
    color: 'white',
    border: 'none',
    padding: '10px 20px',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: 500,
  },
  secondaryButton: {
    backgroundColor: 'transparent',
    border: '1px solid #404040',
    color: '#a0a0a0',
  },
};

export default ErrorBoundary;
