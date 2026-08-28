/**
 * Aegis Journal - Authentication Context
 * 
 * Provides Google Sign-In popup authentication, token management,
 * user aliases, and sign out capabilities.
 */

import React, { createContext, useContext, useEffect, useState, ReactNode, useCallback } from 'react';
import {
  User,
  signInWithPopup,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  getIdTokenResult,
} from 'firebase/auth';
import { collection, addDoc, serverTimestamp } from 'firebase/firestore';
import { auth, googleProvider, db } from '../firebase';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  error: string | null;
  isAdmin: boolean;
  claims: Record<string, any>;
  refreshClaims: () => Promise<void>;
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
  const [isAdmin, setIsAdmin] = useState<boolean>(false);
  const [claims, setClaims] = useState<Record<string, any>>({});
  const [userAliases, setUserAliasesState] = useState<string[]>(() => {
    try {
      const saved = localStorage.getItem('aegis_user_aliases');
      return saved ? JSON.parse(saved) : ['ICICI', 'HDFC', 'Chase', 'Acme Corp', 'Landlord'];
    } catch {
      return ['ICICI', 'HDFC', 'Chase', 'Acme Corp', 'Landlord'];
    }
  });

  const checkClaims = useCallback(async (currentUser: User | null, forceRefresh = false) => {
    if (!currentUser) {
      setIsAdmin(false);
      setClaims({});
      return;
    }
    try {
      const tokenResult = await getIdTokenResult(currentUser, forceRefresh);
      const userClaims = tokenResult.claims || {};
      setClaims(userClaims);
      const adminClaim = userClaims.admin === true || userClaims.role === 'admin';
      setIsAdmin(adminClaim);
    } catch (err) {
      console.warn('[Aegis Auth] Failed to inspect token claims:', err);
    }
  }, []);

  const refreshClaims = useCallback(async () => {
    if (auth.currentUser) {
      await checkClaims(auth.currentUser, true);
    }
  }, [checkClaims]);

  const setUserAliases = (aliases: string[]) => {
    setUserAliasesState(aliases);
    try {
      localStorage.setItem('aegis_user_aliases', JSON.stringify(aliases));
    } catch {}

    // Persist to users/{uid}/profile/aliases in Firestore via server API
    if (user) {
      user.getIdToken().then((token) => {
        if (token) {
          fetch('/api/profile/aliases', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({ aliases }),
          }).catch(() => {});
        }
      });
    }
  };

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      setLoading(false);
      await checkClaims(currentUser);

      if (currentUser) {
        // Tamper-evident audit log for sign-in session
        const sessionKey = `aegis_signin_logged_${currentUser.uid}`;
        if (!sessionStorage.getItem(sessionKey)) {
          sessionStorage.setItem(sessionKey, 'true');
          addDoc(collection(db, 'users', currentUser.uid, 'auditLogs'), {
            action: 'sign-in',
            ts: serverTimestamp(),
            metadata: { provider: 'google.com' },
          }).catch(async (auditErr) => {
            console.warn('[Aegis Auth] Client audit log write error, dispatching to server:', auditErr);
            try {
              const token = await currentUser.getIdToken();
              if (token) {
                fetch('/api/audit', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${token}`,
                  },
                  body: JSON.stringify({
                    action: 'sign-in',
                    metadata: { provider: 'google.com' },
                  }),
                }).catch(() => {});
              }
            } catch {}
          });
        }

        try {
          const token = await currentUser.getIdToken();
          if (token) {
            const res = await fetch('/api/profile/aliases', {
              headers: { Authorization: `Bearer ${token}` },
            });
            if (res.ok) {
              const data = await res.json();
              if (Array.isArray(data.aliases) && data.aliases.length > 0) {
                setUserAliasesState(data.aliases);
                try {
                  localStorage.setItem('aegis_user_aliases', JSON.stringify(data.aliases));
                } catch {}
              }
            }
          }
        } catch (err) {
          console.error('[Aegis Auth] Failed to load server aliases:', err);
        }
      }
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
      const cred = await signInWithPopup(auth, googleProvider);
      if (cred?.user) {
        addDoc(collection(db, 'users', cred.user.uid, 'auditLogs'), {
          action: 'sign-in',
          ts: serverTimestamp(),
          metadata: { provider: 'google.com' },
        }).catch(async () => {
          try {
            const token = await cred.user.getIdToken();
            if (token) {
              fetch('/api/audit', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  Authorization: `Bearer ${token}`,
                },
                body: JSON.stringify({
                  action: 'sign-in',
                  metadata: { provider: 'google.com' },
                }),
              }).catch(() => {});
            }
          } catch {}
        });
      }
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
        isAdmin,
        claims,
        refreshClaims,
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
