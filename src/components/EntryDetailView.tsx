/**
 * Aegis Journal - Entry Detail & Multi-Turn Conversation View
 * 
 * Supports dual-view inspection (Rehydrated Owner vs Canonical Redacted),
 * multi-turn reflective dialogue, and token badge diagnostics.
 */

import React, { useState, useEffect } from 'react';
import {
  ArrowLeft,
  Eye,
  Lock,
  Sparkles,
  Send,
  User,
  Bot,
  ShieldCheck,
  Tag,
  Clock,
  Loader2,
  AlertCircle,
} from 'lucide-react';
import { JournalEntry, EntryMessage } from '../types';
import { useAuth } from '../context/AuthContext';

interface EntryDetailViewProps {
  entry: JournalEntry;
  onBack: () => void;
}

export const EntryDetailView: React.FC<EntryDetailViewProps> = ({ entry, onBack }) => {
  const { getIdToken, userAliases } = useAuth();
  const [viewMode, setViewMode] = useState<'rehydrated' | 'redacted'>('rehydrated');
  const [messages, setMessages] = useState<EntryMessage[]>(entry.messages || []);
  const [inputText, setInputText] = useState('');
  const [isLoadingMessages, setIsLoadingMessages] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch full conversation history on mount if not provided
  useEffect(() => {
    let isMounted = true;
    const fetchThread = async () => {
      if (entry.messages && entry.messages.length > 0) return;
      setIsLoadingMessages(true);
      try {
        const idToken = await getIdToken();
        if (!idToken) return;

        const res = await fetch(`/api/entries/${entry.id}`, {
          headers: { Authorization: `Bearer ${idToken}` },
        });
        if (res.ok && isMounted) {
          const data = await res.json();
          if (data.messages) {
            setMessages(data.messages);
          }
        }
      } catch (err) {
        console.error('Failed to load thread:', err);
      } finally {
        if (isMounted) setIsLoadingMessages(false);
      }
    };

    fetchThread();
    return () => {
      isMounted = false;
    };
  }, [entry.id, getIdToken]);

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim() || isSending) return;

    const currentText = inputText.trim();
    setIsSending(true);
    setError(null);

    try {
      const idToken = await getIdToken();
      if (!idToken) throw new Error('Authentication expired. Please sign in again.');

      const response = await fetch(`/api/entries/${entry.id}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${idToken}`,
        },
        body: JSON.stringify({
          text: currentText,
          userAliases,
        }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || 'Failed to send message.');
      }

      const result = await response.json();
      setMessages((prev) => [
        ...prev,
        result.userMessage,
        result.modelMessage,
      ]);
      setInputText('');
    } catch (err: any) {
      console.error('Failed to send multi-turn reply:', err);
      setError(err?.message || 'Failed to send reply.');
    } finally {
      setIsSending(false);
    }
  };

  const counts = entry.redactionSummary?.counts || {};
  const totalRedactions = (Object.values(counts) as number[]).reduce((a, b) => Number(a) + Number(b), 0);

  return (
    <div id="entry-detail-view" className="max-w-4xl mx-auto px-4 sm:px-6 py-8 text-gray-200">
      {/* Top Bar with Back Navigation and View Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-[#222]">
        <button
          onClick={onBack}
          className="inline-flex items-center gap-2 text-xs sm:text-sm font-medium text-gray-300 hover:text-white bg-[#141414] hover:bg-[#1A1A1A] border border-[#222] px-3 py-1.5 rounded-lg transition-colors w-fit cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Reflections</span>
        </button>

        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500 font-mono hidden sm:inline">Storage Perspective:</span>
          <div className="bg-[#141414] p-1 rounded-lg flex items-center gap-1 text-xs border border-[#222]">
            <button
              onClick={() => setViewMode('rehydrated')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md font-medium transition-all cursor-pointer ${
                viewMode === 'rehydrated'
                  ? 'bg-[#252525] text-white shadow-xs'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Owner View</span>
            </button>
            <button
              onClick={() => setViewMode('redacted')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md font-medium transition-all cursor-pointer ${
                viewMode === 'redacted'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800 shadow-xs'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Canonical Record</span>
            </button>
          </div>
        </div>
      </div>

      {/* Entry Header & Redaction Diagnosis */}
      <div className="bg-[#0F0F0F] border border-[#222] rounded-xl p-5 sm:p-6 mb-6 shadow-md">
        <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
          <h1 className="text-xl sm:text-2xl font-serif font-bold text-white tracking-tight">
            {entry.title}
          </h1>
          <div className="flex items-center gap-2 text-xs text-gray-500 font-mono">
            <Clock className="w-3.5 h-3.5" />
            <span>{new Date(entry.createdAt).toLocaleString()}</span>
          </div>
        </div>

        {/* Diagnostic Redaction Badges */}
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <span className="text-[11px] font-medium uppercase tracking-wider text-gray-400 flex items-center gap-1 font-mono">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
            <span>Redaction Gateway:</span>
          </span>
          {totalRedactions === 0 ? (
            <span className="bg-[#141414] text-gray-400 border border-[#333] text-[11px] px-2 py-0.5 rounded font-mono">
              Zero Direct PII Detected (Clean Text)
            </span>
          ) : (
            Object.entries(counts).map(([type, count]) => {
              if (count === 0) return null;
              return (
                <span
                  key={type}
                  className="bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 text-[11px] px-2 py-0.5 rounded font-mono font-medium"
                >
                  [{type} × {count}]
                </span>
              );
            })
          )}
        </div>

        {/* Reflection Body in Selected Perspective */}
        <div className="mt-4 pt-4 border-t border-[#222]">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium uppercase tracking-wider text-gray-400 font-mono">
              {viewMode === 'rehydrated'
                ? 'Your Raw Reflection (Memory View)'
                : 'Canonical Firestore & Gemini Redacted Payload'}
            </span>
            <span className="text-[11px] font-mono text-emerald-500">
              {viewMode === 'redacted' ? 'Encrypted Invariant' : 'Private to Owner'}
            </span>
          </div>

          <div
            className={`p-4 rounded-xl text-sm leading-relaxed font-sans ${
              viewMode === 'redacted'
                ? 'bg-[#0A0A0A] text-emerald-300 font-mono text-xs border border-emerald-900/50'
                : 'bg-[#141414] text-gray-200 border border-[#222]'
            }`}
          >
            {viewMode === 'redacted'
              ? entry.redactedContent
              : entry.rehydratedContent || entry.redactedContent}
          </div>
        </div>
      </div>

      {/* Multi-Turn Conversation Thread */}
      <div className="space-y-4 mb-6">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-gray-400 px-1 font-mono">
          <Sparkles className="w-4 h-4 text-emerald-400" />
          <span>Reflective Dialogue & Inquiry</span>
        </div>

        {isLoadingMessages ? (
          <div className="p-8 text-center bg-[#0F0F0F] rounded-xl border border-[#222] text-gray-400 text-xs flex items-center justify-center gap-2 font-mono">
            <Loader2 className="w-4 h-4 animate-spin text-emerald-500" />
            <span>Loading conversation thread...</span>
          </div>
        ) : messages.length === 0 ? (
          <div className="p-6 bg-[#0F0F0F] rounded-xl border border-[#222] text-center text-xs text-gray-500">
            No conversation messages recorded yet.
          </div>
        ) : (
          messages.map((msg, index) => {
            const isModel = msg.role === 'model';
            return (
              <div
                key={msg.id || index}
                className={`p-5 rounded-xl border transition-all ${
                  isModel
                    ? 'bg-[#0F1714] border-emerald-900/40 shadow-sm'
                    : 'bg-[#141414] border-[#222] ml-6 sm:ml-12'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-2.5">
                  <div className="flex items-center gap-2">
                    <div
                      className={`w-6 h-6 rounded-md flex items-center justify-center text-xs ${
                        isModel
                          ? 'bg-emerald-600 text-white'
                          : 'bg-[#222] text-gray-300'
                      }`}
                    >
                      {isModel ? <Bot className="w-3.5 h-3.5" /> : <User className="w-3.5 h-3.5" />}
                    </div>
                    <span className="font-semibold text-xs text-white">
                      {isModel ? 'Aegis Reflection Companion' : 'You'}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-[11px] text-gray-500 font-mono">
                    {isModel && msg.modelUsed && (
                      <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-1.5 py-0.5 rounded text-[10px]">
                        {msg.modelUsed}
                      </span>
                    )}
                    <span>{new Date(msg.createdAt).toLocaleTimeString()}</span>
                  </div>
                </div>

                <div className={`text-xs sm:text-sm leading-relaxed whitespace-pre-wrap ${isModel ? 'text-emerald-50/90 font-serif italic' : 'text-gray-200'}`}>
                  {msg.text}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Multi-turn Chat Input Box */}
      <form onSubmit={handleSendMessage} className="bg-[#0F0F0F] border border-[#222] rounded-xl p-4 shadow-md">
        {error && (
          <div className="mb-3 p-3 bg-rose-950/40 border border-rose-800 text-rose-300 text-xs rounded-lg flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex items-center gap-2">
          <input
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Reply to the reflection or explore why this financial moment felt stressful..."
            disabled={isSending}
            className="flex-1 px-3.5 py-2.5 bg-[#141414] border border-[#333] rounded-lg text-xs sm:text-sm text-white placeholder-gray-600 focus:outline-hidden focus:border-emerald-500 transition-all font-sans"
          />

          <button
            type="submit"
            disabled={isSending || !inputText.trim()}
            className="inline-flex items-center gap-1.5 bg-white hover:bg-gray-200 active:bg-gray-300 text-black text-xs sm:text-sm font-semibold px-4 py-2.5 rounded-lg shadow-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            {isSending ? (
              <Loader2 className="w-4 h-4 animate-spin text-black" />
            ) : (
              <>
                <span>Send</span>
                <Send className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </div>

        <p className="text-[11px] text-gray-500 mt-2 flex items-center gap-1 font-mono">
          <ShieldCheck className="w-3 h-3 text-emerald-500" />
          <span>Follow-up replies pass through the same server redaction gateway before model invocation.</span>
        </p>
      </form>
    </div>
  );
};
