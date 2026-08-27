/**
 * Aegis Journal - Landing Page
 * 
 * Strict Google Sign-In ONLY (No email/password forms).
 * Highlights Zero-Plaintext Storage Invariant, Server Redaction Gateway,
 * and Non-Advisory Psychological Reflection.
 */

import React from 'react';
import {
  Shield,
  Lock,
  Cpu,
  Database,
  ArrowRight,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  FileKey2,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const LandingView: React.FC = () => {
  const { signInWithGoogle, loading, error } = useAuth();

  return (
    <div id="aegis-landing-container" className="min-h-[calc(100vh-6rem)] bg-[#0A0A0A] text-gray-200 flex flex-col justify-between">
      {/* Hero Section */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6 pt-12 sm:pt-16 pb-12 w-full">
        <div className="text-center max-w-3xl mx-auto mb-10">
          <div className="inline-flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 px-3.5 py-1 rounded-full text-emerald-400 text-xs font-medium mb-6">
            <Lock className="w-3.5 h-3.5 text-emerald-500" />
            <span>Zero-Plaintext Financial Reflection Architecture</span>
          </div>

          <h1 className="text-4xl sm:text-5xl font-serif font-bold text-white tracking-tight leading-tight mb-5">
            Reflect honestly on your finances with{' '}
            <span className="text-emerald-400 underline decoration-emerald-500/40 decoration-2">
              absolute privacy
            </span>
            .
          </h1>

          <p className="text-base sm:text-lg text-gray-400 leading-relaxed mb-8 max-w-2xl mx-auto">
            Write uninhibited thoughts on spending, debt, and savings anxiety. Our
            server-side redaction gateway strips every card number, account ID, and personal
            identifier before text reaches the AI model or database storage.
          </p>

          {/* Google Sign-In Action */}
          <div className="flex flex-col items-center justify-center gap-3">
            <button
              id="btn-google-sign-in"
              onClick={signInWithGoogle}
              disabled={loading}
              className="inline-flex items-center justify-center gap-3 bg-white hover:bg-gray-200 active:bg-gray-300 text-black font-semibold px-6 py-3.5 rounded-xl shadow-lg shadow-emerald-950/20 transition-all transform hover:-translate-y-0.5 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer text-sm sm:text-base border border-gray-200"
            >
              {/* Google G Logo SVG */}
              <svg className="w-5 h-5" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"
                />
                <path
                  fill="#34A853"
                  d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.35 24 12 24z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.18 0 9.99 0 12s.45 3.82 1.25 5.42l4.03-3.15z"
                />
                <path
                  fill="#EA4335"
                  d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.35 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"
                />
              </svg>
              <span>{loading ? 'Authenticating with Google...' : 'Continue with Google'}</span>
              <ArrowRight className="w-4 h-4 text-gray-700" />
            </button>

            <span className="text-xs text-gray-500 flex items-center gap-1.5 font-mono">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
              Direct Firebase Federated Auth • No passwords stored
            </span>

            {error && (
              <div className="mt-3 p-3 bg-rose-950/40 border border-rose-800 text-rose-300 text-xs rounded-lg flex items-center gap-2 max-w-md">
                <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
                <span>{error}</span>
              </div>
            )}
          </div>
        </div>

        {/* Security Architecture Pillars */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mt-10">
          <div className="bg-[#0F0F0F] p-5 rounded-xl border border-[#222] text-gray-300">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center mb-3 border border-emerald-500/20">
              <Shield className="w-5 h-5" />
            </div>
            <h3 className="font-semibold text-white text-base mb-1.5">
              Server-Side Redaction Gateway
            </h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Deterministic checksum algorithms strip cards (Luhn check), PAN, Aadhaar, IFSC, UPI handles, and bank accounts prior to model invocation.
            </p>
          </div>

          <div className="bg-[#0F0F0F] p-5 rounded-xl border border-[#222] text-gray-300">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center mb-3 border border-emerald-500/20">
              <Database className="w-5 h-5" />
            </div>
            <h3 className="font-semibold text-white text-base mb-1.5">
              Zero-Plaintext Storage Invariant
            </h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Cloud Firestore exclusively stores canonical redacted records under owner-isolated paths (<code className="bg-[#1A1A1A] text-emerald-400 border border-[#333] px-1 py-0.5 rounded text-[11px] font-mono">users/&#123;uid&#125;/entries</code>).
            </p>
          </div>

          <div className="bg-[#0F0F0F] p-5 rounded-xl border border-[#222] text-gray-300">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center mb-3 border border-emerald-500/20">
              <Sparkles className="w-5 h-5" />
            </div>
            <h3 className="font-semibold text-white text-base mb-1.5">
              Reflective, Non-Advisory AI
            </h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Gemini 3.6 Flash explores behavioral impulses and psychological money patterns. Never provides stock tips, investment, or credit advice.
            </p>
          </div>
        </div>

        {/* Live Transformation Interactive Preview */}
        <div className="mt-12 bg-[#0F0F0F] rounded-xl border border-[#222] overflow-hidden">
          <div className="bg-[#141414] px-5 py-3 border-b border-[#222] flex items-center justify-between text-xs text-gray-300">
            <div className="flex items-center gap-2">
              <FileKey2 className="w-4 h-4 text-emerald-400" />
              <span className="font-medium text-white">Live Redaction Invariant Demonstration</span>
            </div>
            <span className="text-[11px] font-mono text-emerald-500">Server Execution Proof</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-[#222] text-xs">
            <div className="p-4 bg-[#0A0A0A]">
              <span className="text-[11px] font-medium uppercase tracking-wider text-gray-500 block mb-2 font-mono">
                What You Type (In Browser Memory Only)
              </span>
              <p className="font-mono text-gray-300 bg-[#141414] p-3 rounded-lg border border-[#222] leading-relaxed">
                &ldquo;I spent Rs 14,500 on an impulse gadget with card <span className="bg-amber-950/60 text-amber-300 border border-amber-800/80 px-1 rounded font-bold">4111 2222 3333 4444</span>, and my ICICI account <span className="bg-amber-950/60 text-amber-300 border border-amber-800/80 px-1 rounded font-bold">004501234567</span> is low.&rdquo;
              </p>
            </div>

            <div className="p-4 bg-[#0F1714]">
              <span className="text-[11px] font-medium uppercase tracking-wider text-emerald-400 block mb-2 font-mono">
                What Gemini Receives & What Firestore Stores
              </span>
              <p className="font-mono text-gray-300 bg-[#141414] p-3 rounded-lg border border-emerald-900/40 leading-relaxed">
                &ldquo;I spent Rs 14,500 on an impulse gadget with card <span className="bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 px-1.5 py-0.5 rounded font-bold">[CARD_1]</span>, and my <span className="bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 px-1.5 py-0.5 rounded font-bold">[ALIAS_1]</span> account <span className="bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 px-1.5 py-0.5 rounded font-bold">[ACCT_1]</span> is low.&rdquo;
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-[#222] bg-[#0F0F0F] py-4 text-center text-xs text-gray-500">
        <p>Aegis Journal • Encrypted Invariant Reflection Framework • Powered by Google Cloud Run & Gemini</p>
      </footer>
    </div>
  );
};
