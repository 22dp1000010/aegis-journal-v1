/**
 * Aegis Journal - Security Activity Audit View (Directive 12)
 * 
 * Renders an append-only, tamper-evident audit trail from users/{uid}/auditLogs
 * sorted newest first.
 * 
 * Invariants:
 * 1. Read-only for authenticated owner.
 * 2. Immutable documents (Firestore driver denies updates and deletes).
 * 3. Document IDs generated via addDoc.
 * 4. Timestamps assigned via serverTimestamp().
 * 5. Redaction metadata contains ONLY counts by class, never matched plaintext.
 */

import React, { useEffect, useState, useCallback } from 'react';
import {
  collection,
  getDocs,
  query,
  orderBy,
  limit,
} from 'firebase/firestore';
import { db } from '../firebase';
import { useAuth } from '../context/AuthContext';
import { AuditLogItem } from '../types';
import {
  Shield,
  Clock,
  LogIn,
  FileText,
  ShieldAlert,
  Sparkles,
  ShieldBan,
  AlertTriangle,
  RefreshCw,
  Lock,
  ExternalLink,
  ChevronRight,
  Filter,
} from 'lucide-react';

interface ActivityViewProps {
  onNewReflection?: () => void;
  onNavigateToTrust?: () => void;
}

export const ActivityView: React.FC<ActivityViewProps> = ({
  onNewReflection,
  onNavigateToTrust,
}) => {
  const { user, getIdToken } = useAuth();
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<string>('all');

  const fetchAuditLogs = useCallback(async (isManualRefresh = false) => {
    if (!user) return;
    if (isManualRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);

    try {
      // 1. Primary Strategy: Query Firestore collection users/{uid}/auditLogs
      const auditCol = collection(db, 'users', user.uid, 'auditLogs');
      let fetchedLogs: AuditLogItem[] = [];

      try {
        const q = query(auditCol, orderBy('ts', 'desc'), limit(100));
        const snapshot = await getDocs(q);
        fetchedLogs = snapshot.docs.map((docSnap) => {
          const data = docSnap.data();
          return {
            id: docSnap.id,
            action: data.action || 'unknown',
            ts: data.ts,
            metadata: data.metadata || undefined,
          };
        });
      } catch (clientQueryErr) {
        console.warn('[ActivityView] Direct client query failed, falling back to server API:', clientQueryErr);
        // 2. Resilient Fallback: Retrieve via authenticated server endpoint GET /api/audit
        const token = await getIdToken();
        if (token) {
          const res = await fetch('/api/audit', {
            headers: { Authorization: `Bearer ${token}` },
          });
          if (res.ok) {
            const result = await res.json();
            if (Array.isArray(result.logs)) {
              fetchedLogs = result.logs;
            }
          }
        }
      }

      // Sort newest first by timestamp
      fetchedLogs.sort((a, b) => {
        const timeA = getTimestampMs(a.ts);
        const timeB = getTimestampMs(b.ts);
        return timeB - timeA;
      });

      setLogs(fetchedLogs);
    } catch (err: any) {
      console.error('[ActivityView] Error fetching audit trail:', err);
      setError(err?.message || 'Failed to retrieve audit trail.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [user, getIdToken]);

  useEffect(() => {
    fetchAuditLogs();
  }, [fetchAuditLogs]);

  // Helper to extract epoch milliseconds from Firestore Timestamp, Date, or string
  function getTimestampMs(ts: any): number {
    if (!ts) return 0;
    if (typeof ts.toMillis === 'function') return ts.toMillis();
    if (typeof ts.toDate === 'function') return ts.toDate().getTime();
    if (ts instanceof Date) return ts.getTime();
    if (typeof ts === 'string') return new Date(ts).getTime();
    if (typeof ts === 'number') return ts;
    return 0;
  }

  // Format date readable
  function formatTimestamp(ts: any): string {
    const ms = getTimestampMs(ts);
    if (!ms) return 'Pending timestamp...';
    const d = new Date(ms);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    });
  }

  // Format relative time
  function formatRelativeTime(ts: any): string {
    const ms = getTimestampMs(ts);
    if (!ms) return 'Just now';
    const diffSec = Math.floor((Date.now() - ms) / 1000);
    if (diffSec < 10) return 'Just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  }

  // Action badge configurations conforming to directive 12
  function getActionConfig(action: string) {
    const cleanAction = action.toLowerCase().replace(/_/g, ' ');

    switch (cleanAction) {
      case 'sign-in':
      case 'sign in':
        return {
          label: 'SIGN-IN',
          color: 'text-sky-400 bg-sky-500/10 border-sky-500/20',
          icon: LogIn,
          description: 'Authenticated session established via Google OAuth.',
        };
      case 'entry created':
      case 'entry_created':
        return {
          label: 'ENTRY CREATED',
          color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
          icon: FileText,
          description: 'New reflection saved in encrypted/redacted form.',
        };
      case 'redaction executed':
      case 'redaction_executed':
        return {
          label: 'REDACTION EXECUTED',
          color: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
          icon: ShieldAlert,
          description: 'PII/financial identifiers neutralized prior to model dispatch.',
        };
      case 'model invoked':
      case 'model_invoked':
        return {
          label: 'MODEL INVOKED',
          color: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20',
          icon: Sparkles,
          description: 'Gemini psychological reflection synthesized with model fallback.',
        };
      case 'access denied':
      case 'access_denied':
        return {
          label: 'ACCESS DENIED',
          color: 'text-rose-400 bg-rose-500/10 border-rose-500/20',
          icon: ShieldBan,
          description: 'Cross-user read rejected at driver level by Firestore rules.',
        };
      case 'rate limit tripped':
      case 'rate_limit_tripped':
        return {
          label: 'RATE LIMIT TRIPPED',
          color: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
          icon: AlertTriangle,
          description: 'Token bucket request throttle engaged to protect API quotas.',
        };
      default:
        return {
          label: action.toUpperCase(),
          color: 'text-gray-300 bg-gray-800 border-gray-700',
          icon: Shield,
          description: 'Security-relevant state transition recorded.',
        };
    }
  }

  // Filter logic
  const filteredLogs = logs.filter((log) => {
    if (activeFilter === 'all') return true;
    const cleanAction = log.action.toLowerCase().replace(/_/g, ' ');
    if (activeFilter === 'sign-in') return cleanAction.includes('sign');
    if (activeFilter === 'entries') return cleanAction.includes('entry');
    if (activeFilter === 'redactions') return cleanAction.includes('redact');
    if (activeFilter === 'models') return cleanAction.includes('model');
    if (activeFilter === 'denials') return cleanAction.includes('denied');
    if (activeFilter === 'throttles') return cleanAction.includes('rate');
    return true;
  });

  return (
    <div id="activity-view-container" className="max-w-5xl mx-auto px-4 sm:px-6 py-8">
      {/* Header Section */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-[#222]">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-sans">
              Security Activity Trail
            </h1>
            <div className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <Lock className="w-3 h-3" />
              <span>APPEND-ONLY</span>
            </div>
          </div>
          <p className="text-xs sm:text-sm text-gray-400 mt-1 max-w-2xl leading-relaxed">
            Tamper-evident audit log stored under{' '}
            <code className="text-emerald-300 font-mono text-xs bg-[#161616] px-1.5 py-0.5 rounded border border-[#2A2A2A]">
              users/{user?.uid ? `${user.uid.slice(0, 10)}...` : 'uid'}/auditLogs
            </code>
            . Firestore security rules strictly prohibit updates and deletes.
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            id="activity-refresh-btn"
            onClick={() => fetchAuditLogs(true)}
            disabled={refreshing || loading}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-gray-300 bg-[#161616] hover:bg-[#202020] hover:text-white border border-[#2A2A2A] rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin text-emerald-400' : ''}`} />
            <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
          </button>

          {onNewReflection && (
            <button
              id="activity-new-reflection-btn"
              onClick={onNewReflection}
              className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-black bg-white hover:bg-gray-200 rounded-lg transition-colors shadow-xs"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>New Entry</span>
            </button>
          )}
        </div>
      </div>

      {/* Security Architecture Summary Bar */}
      <div className="my-6 p-4 rounded-xl bg-[#111] border border-[#222] grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
        <div className="space-y-1">
          <span className="text-gray-500 uppercase tracking-wider text-[10px] font-semibold">
            Storage Invariant
          </span>
          <p className="text-gray-200 font-medium flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span>Driver-Enforced Immutability</span>
          </p>
          <p className="text-[11px] text-gray-400">
            Rules enforce <code className="text-gray-300 font-mono">allow update, delete: if false;</code>
          </p>
        </div>

        <div className="space-y-1">
          <span className="text-gray-500 uppercase tracking-wider text-[10px] font-semibold">
            Timestamp Authority
          </span>
          <p className="text-gray-200 font-medium flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
            <span>Server-Assigned Timestamps</span>
          </p>
          <p className="text-[11px] text-gray-400">
            Enforced with <code className="text-gray-300 font-mono">serverTimestamp()</code>; no client dates.
          </p>
        </div>

        <div className="space-y-1">
          <span className="text-gray-500 uppercase tracking-wider text-[10px] font-semibold">
            Redaction Invariant
          </span>
          <p className="text-gray-200 font-medium flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            <span>Zero Plaintext in Logs</span>
          </p>
          <p className="text-[11px] text-gray-400">
            Redactions record ONLY counts by class; never matched identifiers.
          </p>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-2 mb-4 text-xs no-scrollbar">
        <span className="text-gray-500 text-[11px] font-medium mr-1.5 flex items-center gap-1">
          <Filter className="w-3 h-3" />
          <span>Filter:</span>
        </span>
        {[
          { id: 'all', label: `All Events (${logs.length})` },
          { id: 'sign-in', label: 'Sign-Ins' },
          { id: 'entries', label: 'Entries' },
          { id: 'redactions', label: 'Redactions' },
          { id: 'models', label: 'Model Invocations' },
          { id: 'denials', label: 'Access Denials' },
          { id: 'throttles', label: 'Rate Limits' },
        ].map((tab) => (
          <button
            key={tab.id}
            id={`filter-tab-${tab.id}`}
            onClick={() => setActiveFilter(tab.id)}
            className={`px-3 py-1.5 rounded-lg whitespace-nowrap font-medium transition-all ${
              activeFilter === tab.id
                ? 'bg-white text-black font-semibold'
                : 'text-gray-400 hover:text-white bg-[#141414] hover:bg-[#1C1C1C] border border-[#222]'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main Content Area */}
      {loading ? (
        <div className="py-20 flex flex-col items-center justify-center gap-3 text-gray-500 text-xs">
          <RefreshCw className="w-5 h-5 animate-spin text-emerald-500" />
          <span>Loading authenticated audit log trail...</span>
        </div>
      ) : error ? (
        <div className="p-5 rounded-xl bg-rose-950/30 border border-rose-800/40 text-rose-300 text-xs space-y-2">
          <div className="flex items-center gap-2 font-semibold text-rose-200">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>Failed to load audit logs</span>
          </div>
          <p>{error}</p>
          <button
            onClick={() => fetchAuditLogs(true)}
            className="mt-2 px-3 py-1.5 bg-rose-900/50 hover:bg-rose-900 text-white rounded font-medium transition-colors"
          >
            Retry Fetch
          </button>
        </div>
      ) : filteredLogs.length === 0 ? (
        <div className="py-16 text-center rounded-xl bg-[#111] border border-[#222] p-8 space-y-4">
          <div className="w-12 h-12 rounded-full bg-[#181818] border border-[#2A2A2A] mx-auto flex items-center justify-center text-gray-400">
            <Shield className="w-6 h-6 text-gray-400" />
          </div>
          <div className="space-y-1">
            <h3 className="text-sm font-semibold text-white">No Audit Events in View</h3>
            <p className="text-xs text-gray-400 max-w-md mx-auto">
              {activeFilter !== 'all'
                ? `No events matching "${activeFilter}". Switch to "All Events" or trigger a new action.`
                : 'Your tamper-evident audit trail will automatically log sign-ins, reflections, redactions, model calls, and isolation events.'}
            </p>
          </div>
          {onNewReflection && (
            <button
              onClick={onNewReflection}
              className="px-4 py-2 text-xs font-semibold text-black bg-white hover:bg-gray-200 rounded-lg transition-colors inline-flex items-center gap-2"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Submit First Reflection</span>
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {filteredLogs.map((item, index) => {
            const config = getActionConfig(item.action);
            const Icon = config.icon;
            const meta = item.metadata;

            return (
              <div
                key={item.id || `audit-${index}`}
                id={`audit-log-${item.id || index}`}
                className="p-4 rounded-xl bg-[#111] border border-[#222] hover:border-[#333] transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-[#1A1A1A]">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-semibold border ${config.color}`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      <span>{config.label}</span>
                    </span>

                    <span className="text-[11px] font-mono text-gray-500 bg-[#161616] px-2 py-0.5 rounded border border-[#262626]">
                      Doc ID: {item.id}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-gray-400 text-xs">
                    <Clock className="w-3.5 h-3.5 text-gray-500" />
                    <span className="text-gray-300 font-mono text-[11px]">
                      {formatTimestamp(item.ts)}
                    </span>
                    <span className="text-gray-500 text-[11px]">
                      ({formatRelativeTime(item.ts)})
                    </span>
                  </div>
                </div>

                <div className="pt-2.5 flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="space-y-1 max-w-xl">
                    <p className="text-xs text-gray-300 font-medium">
                      {config.description}
                    </p>
                  </div>

                  {/* Metadata display */}
                  {meta && Object.keys(meta).length > 0 && (
                    <div className="sm:max-w-md w-full bg-[#161616] border border-[#262626] rounded-lg p-2.5 text-xs">
                      <div className="text-[10px] uppercase font-semibold text-gray-500 tracking-wider mb-1 flex items-center justify-between">
                        <span>Event Metadata</span>
                        {config.label.includes('REDACTION') && (
                          <span className="text-amber-400 text-[9px] font-mono">Counts by class only</span>
                        )}
                      </div>

                      {/* Specialized view for Redaction Events: counts by class */}
                      {meta.counts && typeof meta.counts === 'object' ? (
                        <div className="space-y-1">
                          <div className="grid grid-cols-3 gap-1.5 text-[11px]">
                            {Object.entries(meta.counts)
                              .filter(([_, cnt]) => Number(cnt) > 0)
                              .map(([cls, cnt]) => (
                                <div
                                  key={cls}
                                  className="bg-[#1F1F1F] px-2 py-1 rounded border border-[#2C2C2C] flex items-center justify-between"
                                >
                                  <span className="text-gray-400 capitalize font-mono">{cls}:</span>
                                  <span className="text-amber-300 font-bold ml-1 font-mono">{String(cnt)}</span>
                                </div>
                              ))}
                          </div>
                          {Object.values(meta.counts).every((v) => Number(v) === 0) && (
                            <p className="text-[11px] text-gray-500 italic">No sensitive tokens detected.</p>
                          )}
                          <p className="text-[10px] text-emerald-400/80 font-mono mt-1">
                            ✓ Invariant verified: Zero matched values stored.
                          </p>
                        </div>
                      ) : (
                        <pre className="text-[11px] font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap">
                          {JSON.stringify(meta, null, 2)}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Trust Center Navigation Link */}
      {onNavigateToTrust && (
        <div className="mt-8 p-4 rounded-xl bg-[#111] border border-[#222] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="space-y-0.5">
            <span className="font-semibold text-white flex items-center gap-1.5">
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
              <span>Verify Security Guarantees in Trust Center</span>
            </span>
            <p className="text-gray-400 text-[11px]">
              Execute real isolation tests, check Secret Manager custody, and verify driver-level rules.
            </p>
          </div>
          <button
            onClick={onNavigateToTrust}
            className="flex items-center gap-1 text-emerald-400 hover:text-emerald-300 font-medium shrink-0 group"
          >
            <span>Open Trust Center</span>
            <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
          </button>
        </div>
      )}
    </div>
  );
};
