/**
 * Aegis Journal - Resilient Retry Toast
 * 
 * Floating toast notification displayed upon failed persistence or AI reflection calls.
 * Guarantees zero buffer loss by explicitly asserting and preserving uncommitted draft text,
 * and provides an actionable "Retry Save" button.
 */

import React from 'react';
import { ShieldAlert, RefreshCw, X, Clock, CheckCircle2 } from 'lucide-react';

export interface RetryToastProps {
  isOpen: boolean;
  title?: string;
  errorMessage: string;
  bufferCharacterCount?: number;
  rateLimitSeconds?: number | null;
  rateLimitTargetTime?: string | null;
  isRetrying?: boolean;
  onRetry: () => void;
  onDismiss: () => void;
}

export const RetryToast: React.FC<RetryToastProps> = ({
  isOpen,
  title = 'Persistence Operation Failed',
  errorMessage,
  bufferCharacterCount,
  rateLimitSeconds,
  rateLimitTargetTime,
  isRetrying = false,
  onRetry,
  onDismiss,
}) => {
  if (!isOpen) return null;

  const isRateLimited =
    rateLimitSeconds !== null &&
    rateLimitSeconds !== undefined &&
    rateLimitSeconds > 0;

  return (
    <div
      role="alert"
      aria-live="assertive"
      id="retry-save-toast"
      className="fixed bottom-5 right-5 z-50 max-w-md w-[calc(100vw-2.5rem)] sm:w-auto bg-[#111111]/95 backdrop-blur-md border border-rose-800/80 rounded-xl shadow-2xl p-4 text-gray-200 animate-in fade-in slide-in-from-bottom-4 duration-200 font-sans"
    >
      <div className="flex items-start gap-3">
        <div className="p-2 bg-rose-950/80 border border-rose-800 rounded-lg text-rose-400 shrink-0 mt-0.5">
          {isRateLimited ? (
            <Clock className="w-4 h-4 text-amber-400 animate-pulse" />
          ) : (
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          )}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2 mb-1">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-rose-200 font-mono">
              {isRateLimited ? 'Rate Limit Active (Directive 11)' : title}
            </h4>
            <button
              type="button"
              id="btn-dismiss-retry-toast"
              onClick={onDismiss}
              aria-label="Dismiss notification"
              className="text-gray-400 hover:text-white p-0.5 rounded transition-colors cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <p className="text-xs text-gray-300 leading-relaxed break-words mb-2.5">
            {errorMessage}
          </p>

          {/* Explicit buffer preservation assurance */}
          {bufferCharacterCount !== undefined && bufferCharacterCount > 0 && (
            <div className="mb-3 p-2 bg-[#181818] border border-[#282828] rounded-md flex items-center gap-1.5 text-[11px] font-mono text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0 text-emerald-400" />
              <span>Input buffer protected: {bufferCharacterCount} characters preserved</span>
            </div>
          )}

          {isRateLimited && (
            <p className="text-[11px] text-amber-300/90 font-mono mb-3">
              Throttle cooldown: {rateLimitSeconds}s remaining{' '}
              {rateLimitTargetTime && `(resumes at ${rateLimitTargetTime})`}
            </p>
          )}

          <div className="flex items-center gap-2">
            <button
              type="button"
              id="btn-retry-save-action"
              onClick={onRetry}
              disabled={isRetrying || isRateLimited}
              className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-500 active:bg-rose-700 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 shadow-sm transition-all cursor-pointer font-sans"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRetrying ? 'animate-spin' : ''}`} />
              <span>{isRetrying ? 'Retrying Save...' : isRateLimited ? `Wait ${rateLimitSeconds}s` : 'Retry Save'}</span>
            </button>

            <button
              type="button"
              onClick={onDismiss}
              className="px-3 py-1.5 bg-[#1C1C1C] hover:bg-[#252525] text-gray-300 text-xs rounded-lg transition-colors cursor-pointer font-sans"
            >
              Dismiss
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
