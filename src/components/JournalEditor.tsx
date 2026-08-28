/**
 * Aegis Journal - Financial Reflection Editor
 * 
 * Secure entry creation with prompt templates, alias tagging,
 * and resilient submit handlers preserving buffer on failure.
 */

import React, { useState, useEffect } from 'react';
import {
  PenLine,
  Sparkles,
  ShieldAlert,
  HelpCircle,
  Tag,
  ArrowRight,
  Loader2,
  CheckCircle2,
  RefreshCw,
  Clock,
  AlertTriangle,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { JournalEntry } from '../types';
import { RetryToast } from './RetryToast';

interface JournalEditorProps {
  onEntryCreated: (entry: JournalEntry) => void;
  onOpenAliasManager: () => void;
}

const PROMPT_STARTERS = [
  {
    label: 'Impulse Spending',
    title: 'Overspending on Dining & Gadgets',
    text: 'I overspent on dining out again, and my ICICI account 004501234567 is down to Rs 12,000. I felt exhausted after work and bought food to comfort myself.',
  },
  {
    label: 'Credit Anxiety',
    title: 'Post-Statement Credit Stress',
    text: 'Paid the minimum due on card 4111-2222-3333-4444. Salary from Acme Corp came in at Rs 75,000, but I feel terrified of checking my savings account.',
  },
  {
    label: 'Scarcity vs Growth',
    title: 'Guilt Around Self-Care Purchases',
    text: 'Spent Rs 4,500 on dental care with UPI vpa alex@okhdfcbank. Even though it is essential healthcare, I feel guilty for spending money on myself.',
  },
];

export const JournalEditor: React.FC<JournalEditorProps> = ({
  onEntryCreated,
  onOpenAliasManager,
}) => {
  const { getIdToken, userAliases } = useAuth();
  const [title, setTitle] = useState('');
  const [content, setContent] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStep, setSubmitStep] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isToastOpen, setIsToastOpen] = useState(false);
  const [rateLimitSeconds, setRateLimitSeconds] = useState<number | null>(null);
  const [rateLimitTargetTime, setRateLimitTargetTime] = useState<string | null>(null);

  // Active countdown timer for rate limit cooldown (Directive 11)
  useEffect(() => {
    if (rateLimitSeconds === null || rateLimitSeconds <= 0) return;
    const interval = setInterval(() => {
      setRateLimitSeconds((prev) => {
        if (prev === null || prev <= 1) {
          clearInterval(interval);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [rateLimitSeconds]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim() || content.trim().length < 5) {
      setErrorMessage('Please enter at least 5 characters for your reflection.');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage(null);
    setIsToastOpen(false);
    setSubmitStep('1. Tokenizing identifiers via Server Redaction Gateway...');

    try {
      const idToken = await getIdToken();
      if (!idToken) {
        throw new Error('Session expired or unauthorized. Please re-authenticate.');
      }

      setSubmitStep('2. Storing canonical redacted record & consulting Gemini...');

      const response = await fetch('/api/entries', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${idToken}`,
        },
        body: JSON.stringify({
          title: title.trim() || 'Financial Reflection',
          content: content.trim(),
          userAliases,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        if (response.status === 429) {
          const retrySec =
            Number(response.headers.get('Retry-After')) ||
            Number(errorData.retryAfterSeconds) ||
            60;
          const targetTime = new Date(Date.now() + retrySec * 1000).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          });
          setRateLimitSeconds(retrySec);
          setRateLimitTargetTime(targetTime);
          setErrorMessage(
            errorData.error ||
              `Rate limit reached. You can submit another reflection in ${retrySec} seconds (available at ${targetTime}).`
          );
          setIsToastOpen(true);
          return;
        }
        throw new Error(
          errorData.error || `Server returned ${response.status}: ${response.statusText}`
        );
      }

      const result = await response.json();
      setSubmitStep('3. Complete! Loading reflection...');
      setIsToastOpen(false);

      // Transition to detail view with newly created entry
      onEntryCreated({
        id: result.id,
        title: result.title,
        redactedContent: result.redactedContent,
        rehydratedContent: result.rehydratedContent,
        redactionSummary: result.redactionSummary,
        createdAt: result.createdAt,
        messages: [
          {
            id: 'm1',
            role: 'model',
            text: result.reflection,
            modelUsed: result.modelUsed,
            createdAt: result.createdAt,
          },
        ],
      });
    } catch (err: any) {
      console.error('[Aegis Journal] Failed to create entry:', err);
      // Input buffer is deliberately preserved so user doesn't lose thoughts!
      setErrorMessage(err?.message || 'Failed to process reflection. Please check your connection and retry.');
      setIsToastOpen(true);
    } finally {
      setIsSubmitting(false);
      setSubmitStep('');
    }
  };

  const applyStarter = (starter: (typeof PROMPT_STARTERS)[0]) => {
    setTitle(starter.title);
    setContent(starter.text);
    setErrorMessage(null);
  };

  return (
    <div id="journal-editor-view" className="max-w-4xl mx-auto px-4 sm:px-6 py-8 text-gray-200">
      {/* Editor Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl sm:text-3xl font-serif font-bold text-white tracking-tight flex items-center gap-2">
              <PenLine className="w-6 h-6 text-emerald-500" />
              <span>Record a Financial Reflection</span>
            </h1>
            <p className="text-sm text-gray-400 mt-1">
              Express your feelings, anxieties, or dilemmas around money. All identifiers are stripped before AI analysis.
            </p>
          </div>

          <button
            onClick={onOpenAliasManager}
            className="hidden sm:flex items-center gap-1.5 text-xs text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 px-2.5 py-1.5 rounded-lg transition-colors font-mono"
          >
            <Tag className="w-3.5 h-3.5" />
            <span>Active Aliases ({userAliases.length})</span>
          </button>
        </div>
      </div>

      {/* Guided Reflection Starters */}
      <div className="mb-6 bg-[#0F0F0F] p-3.5 rounded-xl border border-[#222]">
        <div className="flex items-center gap-2 text-xs font-semibold text-gray-300 mb-2">
          <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
          <span>Quick Reflection Prompts & Examples</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {PROMPT_STARTERS.map((s, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => applyStarter(s)}
              className="text-left p-2.5 bg-[#141414] hover:bg-[#1A1A1A] border border-[#222] hover:border-[#333] rounded-lg text-xs transition-all group cursor-pointer"
            >
              <span className="font-medium text-gray-200 block group-hover:text-emerald-400">
                {s.label}
              </span>
              <span className="text-gray-500 line-clamp-2 mt-0.5 text-[11px]">
                {s.text}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Form */}
      <form onSubmit={handleSubmit} className="bg-[#0F0F0F] border border-[#222] rounded-xl p-5 sm:p-7 shadow-lg">
        {/* Title Input */}
        <div className="mb-4">
          <label htmlFor="reflection-title" className="block text-xs font-medium uppercase tracking-wider text-gray-400 mb-1.5 font-mono">
            Reflection Title (Optional)
          </label>
          <input
            id="reflection-title"
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="e.g., Weekend Splurge Anxiety or Payday Allocation"
            disabled={isSubmitting}
            className="w-full px-3.5 py-2.5 bg-[#141414] border border-[#333] rounded-lg text-sm text-white placeholder-gray-600 focus:outline-hidden focus:border-emerald-500 transition-colors font-sans"
          />
        </div>

        {/* Content Textarea */}
        <div className="mb-4">
          <div className="flex items-center justify-between mb-1.5">
            <label htmlFor="reflection-content" className="block text-xs font-medium uppercase tracking-wider text-gray-400 font-mono">
              Your Financial Reflection
            </label>
            <span className="text-xs text-gray-500 font-mono">
              {content.length} characters
            </span>
          </div>
          <textarea
            id="reflection-content"
            rows={7}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Describe what happened, how you felt when spending or checking balances, and what money fears or impulses surfaced..."
            disabled={isSubmitting}
            className="w-full px-3.5 py-3 bg-[#141414] border border-[#333] rounded-lg text-sm text-white placeholder-gray-600 focus:outline-hidden focus:border-emerald-500 transition-colors leading-relaxed font-sans"
          />
        </div>

        {/* Active Aliases Pill Bar */}
        {userAliases.length > 0 && (
          <div className="mb-5 flex flex-wrap items-center gap-1.5 text-xs text-gray-400">
            <span className="text-[11px] font-medium text-gray-500">Custom Redacted Aliases:</span>
            {userAliases.map((alias, i) => (
              <span
                key={i}
                className="bg-[#141414] text-emerald-400 border border-emerald-900/40 px-2 py-0.5 rounded text-[11px] font-mono"
              >
                {alias}
              </span>
            ))}
            <button
              type="button"
              onClick={onOpenAliasManager}
              className="text-emerald-400 hover:text-emerald-300 underline text-[11px] ml-1"
            >
              Edit
            </button>
          </div>
        )}

        {/* Error Banner with Specific Rate Limit Display (Directive 11) */}
        {errorMessage && (
          rateLimitSeconds !== null && rateLimitSeconds > 0 ? (
            <div className="mb-5 p-4 bg-amber-950/40 border border-amber-800/80 rounded-lg text-amber-200 text-xs flex items-start justify-between gap-3 shadow-sm">
              <div className="flex items-start gap-2.5">
                <Clock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5 animate-pulse" />
                <div>
                  <strong className="font-semibold block text-amber-100 text-sm">Rate Limit Active (Directive 11)</strong>
                  <p className="mt-1 leading-relaxed text-amber-200">
                    Token bucket throttle engaged to protect Gemini quotas. You can retry in{' '}
                    <span className="font-mono font-bold text-amber-300 text-xs bg-amber-900/60 px-1.5 py-0.5 rounded border border-amber-700/50">
                      {rateLimitSeconds}s
                    </span>{' '}
                    {rateLimitTargetTime && `(available at ${rateLimitTargetTime})`}.
                  </p>
                  <p className="text-[11px] text-amber-400/80 mt-1.5 flex items-center gap-1 font-mono">
                    <ShieldAlert className="w-3 h-3 text-amber-400" />
                    <span>Your reflection draft is safely preserved below and will not be lost.</span>
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={handleSubmit}
                disabled={rateLimitSeconds > 0 || isSubmitting}
                className="px-3 py-1.5 bg-amber-900/80 hover:bg-amber-800 text-amber-100 disabled:opacity-40 disabled:cursor-not-allowed rounded-md font-medium text-xs flex items-center gap-1.5 shrink-0 border border-amber-700 transition-all cursor-pointer"
              >
                <RefreshCw className={`w-3 h-3 ${rateLimitSeconds > 0 ? '' : 'text-amber-300'}`} />
                <span>{rateLimitSeconds > 0 ? `Wait ${rateLimitSeconds}s` : 'Retry Now'}</span>
              </button>
            </div>
          ) : (
            <div className="mb-5 p-4 bg-rose-950/40 border border-rose-800 rounded-lg text-rose-300 text-xs flex items-start justify-between gap-3">
              <div className="flex items-start gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="font-semibold block text-rose-200">Reflection Submission Issue</strong>
                  <p className="mt-0.5">{errorMessage}</p>
                  <p className="text-[11px] text-rose-400 mt-1">Your reflection buffer is preserved below.</p>
                </div>
              </div>
              <button
                type="button"
                onClick={handleSubmit}
                className="px-2.5 py-1 bg-rose-700 hover:bg-rose-600 text-white rounded font-medium flex items-center gap-1 shrink-0"
              >
                <RefreshCw className="w-3 h-3" />
                <span>Retry</span>
              </button>
            </div>
          )
        )}

        {/* Submission State Progress */}
        {isSubmitting && submitStep && (
          <div className="mb-5 p-3.5 bg-emerald-950/30 border border-emerald-800/80 rounded-lg text-emerald-300 text-xs flex items-center gap-2.5 animate-pulse font-mono">
            <Loader2 className="w-4 h-4 text-emerald-400 animate-spin shrink-0" />
            <span>{submitStep}</span>
          </div>
        )}

        {/* Action Controls */}
        <div className="flex items-center justify-between pt-4 border-t border-[#222]">
          <div className="flex items-center gap-1.5 text-xs text-gray-500 font-mono">
            <ShieldAlert className="w-3.5 h-3.5 text-emerald-500" />
            <span>Zero-Plaintext Server Execution</span>
          </div>

          <button
            id="btn-submit-reflection"
            type="submit"
            disabled={isSubmitting || !content.trim() || (rateLimitSeconds !== null && rateLimitSeconds > 0)}
            className="inline-flex items-center gap-2 bg-white hover:bg-gray-200 active:bg-gray-300 text-black font-semibold px-5 py-2.5 rounded-lg text-sm shadow-md transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-black" />
                <span>Processing...</span>
              </>
            ) : rateLimitSeconds !== null && rateLimitSeconds > 0 ? (
              <>
                <Clock className="w-4 h-4 text-black animate-pulse" />
                <span>Rate Limited ({rateLimitSeconds}s)</span>
              </>
            ) : (
              <>
                <span>Reflect & Tokenize</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </form>

      {/* Resilient Retry Toast (Directive 6: Never clears user input buffer on failed write) */}
      <RetryToast
        isOpen={isToastOpen}
        title="Reflection Save Failed"
        errorMessage={errorMessage || 'Failed to process financial reflection.'}
        bufferCharacterCount={content.length}
        rateLimitSeconds={rateLimitSeconds}
        rateLimitTargetTime={rateLimitTargetTime}
        isRetrying={isSubmitting}
        onRetry={() => {
          const fakeEvent = { preventDefault: () => {} } as React.FormEvent;
          handleSubmit(fakeEvent);
        }}
        onDismiss={() => setIsToastOpen(false)}
      />
    </div>
  );
};
