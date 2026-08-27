/**
 * Aegis Journal - Authentication Context
 * 
 * Provides Google Sign-In popup authentication, token management,
 * user aliases, and sign out capabilities.
 */

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import {
  User,
  signInWithPopup,
  signOut as firebaseSignOut,
  onAuthStateChanged,
} from 'firebase/auth';
import { auth, googleProvider } from '../firebase';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  error: string | null;
  userAliases: string[];
  setUserAliases: (aliases: string[]) => void;
  getIdToken: () => Promise<string | null>;
  signInWithGoogle: () => Promise<void>;
  signOut: () => Promise<void>;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [userAliases, setUserAliasesState] = useState<string[]>(() => {
    try {
      const saved = localStorage.getItem('aegis_user_aliases');
      return saved ? JSON.parse(saved) : ['ICICI', 'HDFC', 'Chase', 'Acme Corp', 'Landlord'];
    } catch {
      return ['ICICI', 'HDFC', 'Chase', 'Acme Corp', 'Landlord'];
    }
  });

  const setUserAliases = (aliases: string[]) => {
    setUserAliasesState(aliases);
    try {
      localStorage.setItem('aegis_user_aliases', JSON.stringify(aliases));
    } catch {}
  };

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (currentUser) => {
      setUser(currentUser);
      setLoading(false);
    });
    return () => unsubscribe();
  }, []);

  const getIdToken = async (): Promise<string | null> => {
    if (!user) return null;
    try {
      return await user.getIdToken();
    } catch (err: any) {
      console.error('[Aegis Auth] Failed to get ID token:', err);
      return null;
    }
  };

  const signInWithGoogle = async () => {
    setLoading(true);
    setError(null);
    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err: any) {
      console.error('[Aegis Auth] Google Sign-In Error:', err);
      setError(err?.message || 'Google Sign-In failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const signOut = async () => {
    try {
      await firebaseSignOut(auth);
    } catch (err: any) {
      console.error('[Aegis Auth] Sign Out Error:', err);
      setError(err?.message || 'Failed to sign out.');
    }
  };

  const clearError = () => setError(null);

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        error,
        userAliases,
        setUserAliases,
        getIdToken,
        signInWithGoogle,
        signOut,
        clearError,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
