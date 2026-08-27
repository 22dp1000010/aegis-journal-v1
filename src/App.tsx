/**
 * Aegis Journal - Main Application Component
 */

import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { DisclaimerBanner } from './components/DisclaimerBanner';
import { Header } from './components/Header';
import { LandingView } from './components/LandingView';
import { JournalEditor } from './components/JournalEditor';
import { EntryListView } from './components/EntryListView';
import { EntryDetailView } from './components/EntryDetailView';
import { TrustCenter } from './components/TrustCenter';
import { AliasManagerModal } from './components/AliasManagerModal';
import { JournalEntry } from './types';
import { Loader2 } from 'lucide-react';

const MainContent: React.FC = () => {
  const { user, loading } = useAuth();
  const [currentView, setCurrentView] = useState<'editor' | 'list' | 'detail' | 'trust'>('editor');
  const [selectedEntry, setSelectedEntry] = useState<JournalEntry | null>(null);
  const [isAliasModalOpen, setIsAliasModalOpen] = useState(false);

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0A0A0A] flex flex-col items-center justify-center gap-3 text-gray-400 text-xs">
        <Loader2 className="w-6 h-6 animate-spin text-emerald-500" />
        <span className="font-medium">Initializing Aegis Journal Secure Enclave...</span>
      </div>
    );
  }

  // If user is not authenticated, show landing screen with Google Sign-In only
  if (!user) {
    return (
      <div className="min-h-screen bg-[#0A0A0A] flex flex-col text-gray-200">
        <DisclaimerBanner />
        <LandingView />
      </div>
    );
  }

  const handleSelectEntry = (entry: JournalEntry) => {
    setSelectedEntry(entry);
    setCurrentView('detail');
  };

  const handleEntryCreated = (newEntry: JournalEntry) => {
    setSelectedEntry(newEntry);
    setCurrentView('detail');
  };

  const handleNavigate = (view: 'editor' | 'list' | 'trust') => {
    setCurrentView(view);
    setSelectedEntry(null);
  };

  return (
    <div className="min-h-screen bg-[#0A0A0A] flex flex-col text-gray-200 selection:bg-emerald-900 selection:text-emerald-200 font-sans">
      <DisclaimerBanner />
      <Header
        currentView={currentView}
        onNavigate={handleNavigate}
        onOpenAliasManager={() => setIsAliasModalOpen(true)}
      />

      <main className="flex-1 pb-16">
        {currentView === 'editor' && (
          <JournalEditor
            onEntryCreated={handleEntryCreated}
            onOpenAliasManager={() => setIsAliasModalOpen(true)}
          />
        )}

        {currentView === 'list' && (
          <EntryListView
            onSelectEntry={handleSelectEntry}
            onNewReflection={() => setCurrentView('editor')}
          />
        )}

        {currentView === 'detail' && selectedEntry && (
          <EntryDetailView
            entry={selectedEntry}
            onBack={() => setCurrentView('list')}
          />
        )}

        {currentView === 'trust' && <TrustCenter />}
      </main>

      <AliasManagerModal
        isOpen={isAliasModalOpen}
        onClose={() => setIsAliasModalOpen(false)}
      />
    </div>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <MainContent />
    </AuthProvider>
  );
}
