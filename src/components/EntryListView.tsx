/**
 * Aegis Journal - Past Entries Browser
 * 
 * Filterable, searchable repository of all private reflections.
 */

import React, { useState, useEffect } from 'react';
import {
  BookOpen,
  Search,
  PenLine,
  Clock,
  ShieldCheck,
  MessageSquare,
  ArrowRight,
  Filter,
  Loader2,
  RefreshCw,
} from 'lucide-react';
import { JournalEntry } from '../types';
import { useAuth } from '../context/AuthContext';

interface EntryListViewProps {
  onSelectEntry: (entry: JournalEntry) => void;
  onNewReflection: () => void;
}

export const EntryListView: React.FC<EntryListViewProps> = ({
  onSelectEntry,
  onNewReflection,
}) => {
  const { getIdToken } = useAuth();
  const [entries, setEntries] = useState<JournalEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  const fetchEntries = async () => {
    setLoading(true);
    setError(null);
    try {
      const idToken = await getIdToken();
      if (!idToken) throw new Error('Authentication expired.');

      const res = await fetch('/api/entries', {
        headers: { Authorization: `Bearer ${idToken}` },
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || 'Failed to fetch entries.');
      }

      const data = await res.json();
      setEntries(data.entries || []);
    } catch (err: any) {
      console.error('Failed to load past entries:', err);
      setError(err?.message || 'Failed to retrieve past entries.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEntries();
  }, []);

  const filteredEntries = entries.filter((e) => {
    const matchesSearch =
      e.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      e.redactedContent.toLowerCase().includes(searchTerm.toLowerCase());

    if (!matchesSearch) return false;
    if (categoryFilter === 'ALL') return true;
    if (categoryFilter === 'CLEAN') {
      const total = (Object.values(e.redactionSummary?.counts || {}) as number[]).reduce((a, b) => Number(a) + Number(b), 0);
      return total === 0;
    }
    return ((e.redactionSummary?.counts?.[categoryFilter] as number) || 0) > 0;
  });

  return (
    <div id="entry-list-view" className="max-w-5xl mx-auto px-4 sm:px-6 py-8 text-gray-200">
      {/* List Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl sm:text-3xl font-serif font-bold text-white tracking-tight flex items-center gap-2">
            <BookOpen className="w-6 h-6 text-emerald-500" />
            <span>Financial Reflection Archive</span>
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Browse and review your past private reflections and psychological AI summaries.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchEntries}
            disabled={loading}
            title="Refresh entries"
            className="p-2 bg-[#141414] hover:bg-[#1A1A1A] border border-[#222] rounded-lg text-gray-400 hover:text-white transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-emerald-500' : ''}`} />
          </button>

          <button
            id="btn-archive-new-reflection"
            onClick={onNewReflection}
            className="inline-flex items-center gap-2 bg-white hover:bg-gray-200 active:bg-gray-300 text-black text-xs sm:text-sm font-semibold px-4 py-2 rounded-lg shadow-sm transition-all cursor-pointer"
          >
            <PenLine className="w-4 h-4" />
            <span>New Reflection</span>
          </button>
        </div>
      </div>

      {/* Search & Filter Bar */}
      <div className="bg-[#0F0F0F] border border-[#222] rounded-xl p-4 mb-6 shadow-md flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search reflections by topic, keywords, or token..."
            className="w-full pl-9 pr-4 py-2 bg-[#141414] border border-[#333] rounded-lg text-xs sm:text-sm text-white placeholder-gray-600 focus:outline-hidden focus:border-emerald-500 transition-all font-sans"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-gray-500 shrink-0 hidden sm:block" />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="w-full sm:w-auto px-3 py-2 bg-[#141414] border border-[#333] rounded-lg text-xs sm:text-sm text-gray-300 focus:outline-hidden focus:border-emerald-500"
          >
            <option value="ALL">All Categories</option>
            <option value="CARD">Contains Card Tokens</option>
            <option value="ACCT">Contains Bank Accounts</option>
            <option value="UPI">Contains UPI Handles</option>
            <option value="ALIAS">Contains Custom Aliases</option>
            <option value="CLEAN">No PII Detected</option>
          </select>
        </div>
      </div>

      {/* Entries List */}
      {loading ? (
        <div className="p-12 text-center bg-[#0F0F0F] rounded-xl border border-[#222] text-gray-400 text-xs flex flex-col items-center justify-center gap-3">
          <Loader2 className="w-6 h-6 animate-spin text-emerald-500" />
          <span className="font-mono">Retrieving encrypted reflections from Cloud Firestore...</span>
        </div>
      ) : error ? (
        <div className="p-6 bg-rose-950/40 border border-rose-800 rounded-xl text-rose-300 text-xs flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={fetchEntries}
            className="px-3 py-1 bg-rose-700 hover:bg-rose-600 text-white rounded font-medium text-xs"
          >
            Retry
          </button>
        </div>
      ) : filteredEntries.length === 0 ? (
        <div className="p-12 text-center bg-[#0F0F0F] rounded-xl border border-[#222]">
          <BookOpen className="w-10 h-10 text-gray-600 mx-auto mb-3" />
          <h3 className="font-serif font-bold text-white text-base mb-1">
            No reflections found
          </h3>
          <p className="text-xs text-gray-400 max-w-sm mx-auto mb-4">
            {searchTerm || categoryFilter !== 'ALL'
              ? 'Try modifying your search query or category filters.'
              : 'You haven’t recorded any financial reflections yet. Start by exploring your recent spending thoughts.'}
          </p>
          <button
            onClick={onNewReflection}
            className="inline-flex items-center gap-1.5 bg-white hover:bg-gray-200 text-black text-xs font-semibold px-4 py-2 rounded-lg"
          >
            <PenLine className="w-3.5 h-3.5" />
            <span>Create First Reflection</span>
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3.5">
          {filteredEntries.map((entry) => {
            const counts = entry.redactionSummary?.counts || {};
            return (
              <div
                key={entry.id}
                onClick={() => onSelectEntry(entry)}
                className="bg-[#0F0F0F] hover:bg-[#141414] border border-[#222] hover:border-[#333] rounded-xl p-5 transition-all shadow-sm cursor-pointer group"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                  <h3 className="font-serif font-bold text-base text-white group-hover:text-emerald-400 transition-colors">
                    {entry.title}
                  </h3>
                  <div className="flex items-center gap-2 text-xs text-gray-500 font-mono">
                    <Clock className="w-3.5 h-3.5" />
                    <span>{new Date(entry.createdAt).toLocaleDateString()}</span>
                  </div>
                </div>

                <p className="text-xs text-gray-300 line-clamp-2 mb-3 leading-relaxed font-mono text-[11px] bg-[#141414] p-2.5 rounded-md border border-[#222]">
                  {entry.redactedContent}
                </p>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[#222]">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
                    {Object.entries(counts).filter(([_, c]) => Number(c) > 0).length === 0 ? (
                      <span className="text-[10px] bg-[#141414] text-gray-400 border border-[#333] px-1.5 py-0.5 rounded font-mono">
                        Clean Text
                      </span>
                    ) : (
                      Object.entries(counts)
                        .filter(([_, c]) => Number(c) > 0)
                        .map(([type, c]) => (
                          <span
                            key={type}
                            className="text-[10px] bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 px-1.5 py-0.5 rounded font-mono font-medium"
                          >
                            [{type} × {c}]
                          </span>
                        ))
                    )}
                  </div>

                  <div className="flex items-center gap-3 text-xs text-gray-400 font-medium">
                    <span className="flex items-center gap-1 font-mono">
                      <MessageSquare className="w-3.5 h-3.5" />
                      <span>{entry.messageCount || 1} turns</span>
                    </span>
                    <span className="text-emerald-400 group-hover:translate-x-0.5 transition-transform inline-flex items-center gap-0.5 text-xs font-semibold">
                      <span>View</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
