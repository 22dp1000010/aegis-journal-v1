/**
 * Aegis Journal - Custom Redaction Alias Manager Modal
 */

import React, { useState } from 'react';
import { X, Plus, Trash2, Tag, ShieldCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface AliasManagerModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AliasManagerModal: React.FC<AliasManagerModalProps> = ({ isOpen, onClose }) => {
  const { userAliases, setUserAliases } = useAuth();
  const [newAlias, setNewAlias] = useState('');

  if (!isOpen) return null;

  const handleAddAlias = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newAlias.trim();
    if (!trimmed) return;
    if (userAliases.includes(trimmed)) {
      setNewAlias('');
      return;
    }
    setUserAliases([...userAliases, trimmed]);
    setNewAlias('');
  };

  const handleRemoveAlias = (aliasToRemove: string) => {
    setUserAliases(userAliases.filter((a) => a !== aliasToRemove));
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
      <div className="bg-[#0F0F0F] rounded-2xl border border-[#222] max-w-md w-full p-6 shadow-2xl relative text-gray-200 animate-in fade-in zoom-in-95 duration-150">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 text-gray-500 hover:text-white rounded-lg transition-colors cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-2 text-emerald-400 mb-2">
          <Tag className="w-5 h-5" />
          <h2 className="text-lg font-serif font-bold text-white">
            Custom Redacted Aliases
          </h2>
        </div>

        <p className="text-xs text-gray-400 mb-4 leading-relaxed">
          Specify private names (e.g. your employer, landlord, spouse, local bank) that you want automatically replaced with <code className="bg-[#141414] text-emerald-400 border border-[#222] px-1 py-0.5 rounded font-mono text-[11px]">[ALIAS_N]</code>.
        </p>

        {/* Add Input */}
        <form onSubmit={handleAddAlias} className="flex gap-2 mb-4">
          <input
            type="text"
            value={newAlias}
            onChange={(e) => setNewAlias(e.target.value)}
            placeholder="e.g. Acme Corp, ICICI, Landlord"
            className="flex-1 px-3 py-2 bg-[#141414] border border-[#333] rounded-lg text-xs sm:text-sm text-white placeholder-gray-600 focus:bg-[#181818] focus:outline-hidden focus:border-emerald-500 font-sans"
          />
          <button
            type="submit"
            disabled={!newAlias.trim()}
            className="inline-flex items-center gap-1 bg-white hover:bg-gray-200 active:bg-gray-300 text-black text-xs font-semibold px-3.5 py-2 rounded-lg transition-all disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Add</span>
          </button>
        </form>

        {/* Aliases List */}
        <div className="max-h-48 overflow-y-auto space-y-1.5 mb-5 pr-1">
          {userAliases.length === 0 ? (
            <p className="text-center py-4 text-xs text-gray-600 font-mono">
              No custom aliases added yet.
            </p>
          ) : (
            userAliases.map((alias, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between px-3 py-2 bg-[#141414] border border-[#222] rounded-lg text-xs"
              >
                <span className="font-mono text-gray-200">{alias}</span>
                <button
                  type="button"
                  onClick={() => handleRemoveAlias(alias)}
                  className="text-gray-500 hover:text-rose-400 p-1 transition-colors cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))
          )}
        </div>

        <div className="flex items-center justify-between pt-3 border-t border-[#222]">
          <span className="text-[11px] text-gray-500 flex items-center gap-1 font-mono">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
            <span>Saved to user preferences</span>
          </span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-white hover:bg-gray-200 text-black font-semibold rounded-lg text-xs transition-all cursor-pointer"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
