/**
 * Aegis Journal - Client-Side Firebase Initialization
 * 
 * Firebase Authentication with Google Sign-In
 * Cloud Firestore with custom databaseId: 'aegis-journal-dbid'
 */

import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';

const firebaseConfig = {
  apiKey: "AIzaSyBGIZ6p297WnVrg6P_3NWeIjpG-h1siWjk",
  authDomain: "aegis-journal-prod.firebaseapp.com",
  projectId: "aegis-journal-prod",
  storageBucket: "aegis-journal-prod.firebasestorage.app",
  messagingSenderId: "476528162083",
  appId: "1:476528162083:web:4b946515e57aa2bd424896"
};

export const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();
export const auth = getAuth(app);
export const googleProvider = new GoogleAuthProvider();

// Initialize Firestore with the exact non-default database ID: aegis-journal-dbid
export const db = getFirestore(app, 'aegis-journal-dbid');
