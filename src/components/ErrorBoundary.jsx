import React from 'react';

// Catches render-time exceptions anywhere in the popup tree and shows a
// friendly fallback (with the error text + a reload button) instead of a blank
// popup. Class component because error boundaries require lifecycle hooks.

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error('Popup crashed:', error, info);
  }

  handleReload = () => {
    this.setState({ error: null });
    if (typeof window !== 'undefined' && window.location && window.location.reload) {
      window.location.reload();
    }
  };

  render() {
    const { error } = this.state;
    if (error) {
      return (
        <div className="error-boundary">
          <h3>⚠️ Something went wrong</h3>
          <p className="error-boundary-msg">{String((error && error.message) || error)}</p>
          <button className="btn-primary" onClick={this.handleReload}>
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
