/**
 * Aegis Journal - React Error Boundary
 * 
 * Catches unhandled runtime exceptions in the component tree,
 * preventing container-wide crashes and allowing session recovery
 * without loss of authenticated state or unsaved input buffers.
 */

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { ShieldAlert, RefreshCw } from 'lucide-react';

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  public static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      error,
      errorInfo: null,
    };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[Aegis ErrorBoundary caught exception]:', error, errorInfo);
    this.setState({ error, errorInfo });
  }

  private handleRecover = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
    });
  };

  private handleReload = () => {
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div
          role="alert"
          id="react-error-boundary-view"
          className="min-h-screen bg-[#0A0A0A] text-gray-200 flex flex-col items-center justify-center p-6 font-sans selection:bg-emerald-900 selection:text-emerald-200"
        >
          <div className="max-w-md w-full bg-[#0F0F0F] border border-rose-900/60 rounded-2xl p-6 sm:p-8 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-xl bg-rose-950/60 border border-rose-800 flex items-center justify-center text-rose-400 shrink-0">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-base font-semibold text-white">Component Error Caught</h2>
                <p className="text-xs text-gray-400 font-mono">React Error Boundary Isolation</p>
              </div>
            </div>

            <div className="p-3.5 bg-rose-950/20 border border-rose-900/40 rounded-lg mb-4">
              <p className="text-xs font-mono text-rose-300 break-words leading-relaxed">
                {this.state.error?.message || 'An unexpected rendering error occurred.'}
              </p>
            </div>

            <p className="text-xs text-gray-400 mb-6 leading-relaxed">
              A runtime component exception was prevented from crashing the host container.
              Your local authentication state and uncommitted reflection buffers remain safe.
            </p>

            <div className="flex flex-col sm:flex-row items-center gap-3">
              <button
                type="button"
                id="btn-error-boundary-recover"
                onClick={this.handleRecover}
                className="w-full sm:flex-1 py-2.5 px-4 bg-white hover:bg-gray-200 text-black text-xs font-semibold rounded-lg flex items-center justify-center gap-2 transition-all cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Recover Component</span>
              </button>

              <button
                type="button"
                id="btn-error-boundary-reload"
                onClick={this.handleReload}
                className="w-full sm:w-auto py-2.5 px-4 bg-[#141414] hover:bg-[#1C1C1C] border border-[#333] text-gray-300 hover:text-white text-xs font-medium rounded-lg transition-all cursor-pointer"
              >
                Reload App
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
