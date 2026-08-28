/**
 * Aegis Journal - Navigation Header
 */

import React from 'react';
import { Shield, BookOpen, PenLine, KeyRound, LogOut, User as UserIcon, Tag, Activity } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface HeaderProps {
  currentView: 'editor' | 'list' | 'detail' | 'trust' | 'activity';
  onNavigate: (view: 'editor' | 'list' | 'trust' | 'activity') => void;
  onOpenAliasManager: () => void;
}

export const Header: React.FC<HeaderProps> = ({ currentView, onNavigate, onOpenAliasManager }) => {
  const { user, signOut, isAdmin } = useAuth();

  return (
    <header
      id="aegis-app-header"
      className="bg-[#0F0F0F] border-b border-[#222] sticky top-0 z-30 shadow-md"
    >
      <div className="max-w-6xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
        {/* Brand Logo */}
        <div
          id="brand-logo-container"
          onClick={() => onNavigate('editor')}
          className="flex items-center gap-3 cursor-pointer select-none group"
        >
          <div className="w-8 h-8 bg-emerald-600 rounded-lg flex items-center justify-center text-white shadow-lg shadow-emerald-900/20 group-hover:bg-emerald-500 transition-colors">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base sm:text-lg font-semibold tracking-tight text-white uppercase font-sans">
                Aegis Journal
              </span>
              <div className="hidden sm:flex items-center space-x-1.5 text-[11px] font-medium text-emerald-400 bg-emerald-500/10 px-2.5 py-0.5 rounded-full border border-emerald-500/20">
                <div className="w-1.5 h-1.5 bg-emerald-500 rounded-full animate-pulse"></div>
                <span>ZERO-PLAINTEXT</span>
              </div>
            </div>
            <p className="text-[11px] text-gray-500 hidden md:block tracking-wide">
              Private Financial Reflection Gateway
            </p>
          </div>
        </div>

        {/* Navigation Actions */}
        <nav className="flex items-center gap-1.5 sm:gap-2">
          <button
            id="nav-btn-new-reflection"
            onClick={() => onNavigate('editor')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all ${
              currentView === 'editor'
                ? 'bg-white text-black shadow-xs'
                : 'text-gray-400 hover:text-white hover:bg-[#1A1A1A]'
            }`}
          >
            <PenLine className="w-3.5 h-3.5" />
            <span>New Reflection</span>
          </button>

          <button
            id="nav-btn-past-entries"
            onClick={() => onNavigate('list')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all ${
              currentView === 'list'
                ? 'bg-white text-black shadow-xs'
                : 'text-gray-400 hover:text-white hover:bg-[#1A1A1A]'
            }`}
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Past Reflections</span>
          </button>

          <button
            id="nav-btn-activity"
            onClick={() => onNavigate('activity')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all ${
              currentView === 'activity'
                ? 'bg-white text-black shadow-xs'
                : 'text-gray-400 hover:text-white hover:bg-[#1A1A1A]'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Activity</span>
          </button>

          <button
            id="nav-btn-trust-center"
            onClick={() => onNavigate('trust')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs sm:text-sm font-medium rounded-lg transition-all ${
              currentView === 'trust'
                ? 'bg-emerald-600 text-white shadow-xs'
                : 'text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>Trust Center</span>
          </button>

          <button
            id="nav-btn-aliases"
            onClick={onOpenAliasManager}
            title="Configure custom aliases for redaction"
            className="p-2 text-gray-400 hover:text-white hover:bg-[#1A1A1A] rounded-lg transition-colors hidden sm:flex items-center border border-[#222]"
          >
            <Tag className="w-4 h-4" />
          </button>

          {/* User Profile & Sign Out */}
          {user && (
            <div className="flex items-center pl-2 ml-1 border-l border-[#222] gap-2">
              <div className="flex items-center gap-2" title={user.email || user.displayName || ''}>
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt={user.displayName || 'User'}
                    className="w-8 h-8 rounded-full bg-[#222] border border-[#333]"
                    referrerPolicy="no-referrer"
                  />
                ) : (
                  <div className="w-8 h-8 rounded-full bg-[#222] border border-[#333] flex items-center justify-center text-gray-400">
                    <UserIcon className="w-4 h-4" />
                  </div>
                )}
                <span className="text-xs text-gray-300 font-medium hidden lg:inline max-w-[120px] truncate font-mono">
                  {user.displayName || user.email?.split('@')[0]}
                </span>
                {isAdmin && (
                  <span className="text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800/80 px-1.5 py-0.5 rounded hidden sm:inline-block">
                    ADMIN
                  </span>
                )}
              </div>

              <button
                id="btn-sign-out"
                onClick={signOut}
                title="Sign out of Aegis Journal"
                className="p-1.5 text-gray-500 hover:text-rose-400 hover:bg-rose-950/40 rounded-lg transition-colors"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          )}
        </nav>
      </div>
    </header>
  );
};
