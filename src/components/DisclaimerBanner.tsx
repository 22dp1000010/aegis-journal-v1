/**
 * Aegis Journal - Persistent Non-Advisory Disclaimer Banner
 * 
 * Non-dismissible notice clarifying that Aegis Journal provides
 * emotional and behavioral reflections, not financial/tax/credit advice.
 */

import React from 'react';
import { ShieldCheck, Info } from 'lucide-react';

export const DisclaimerBanner: React.FC = () => {
  return (
    <aside
      id="aegis-disclaimer-banner"
      aria-label="Advisory Disclaimer"
      className="bg-[#0A0A0A] border-b border-[#222] text-gray-400 text-xs px-4 py-2.5"
    >
      <div className="max-w-6xl mx-auto flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />
          <p className="leading-tight text-gray-300">
            <strong className="text-white font-medium">Non-Advisory Guardrail:</strong>{' '}
            Aegis Journal provides psychological and behavioral reflections on financial habits. It does{' '}
            <span className="text-emerald-400 font-medium">not</span> offer investment, tax, credit, or legal advice.{' '}
            <span className="hidden sm:inline text-gray-500">
              All financial identifiers are tokenized server-side before reaching AI models or database storage.
            </span>
          </p>
        </div>
        <div className="hidden md:flex items-center gap-1.5 text-gray-500 shrink-0 font-mono text-[11px]">
          <Info className="w-3.5 h-3.5 text-emerald-500" />
          <span className="text-emerald-500/90 font-medium">Canonical DB: Redacted Only</span>
        </div>
      </div>
    </aside>
  );
};
