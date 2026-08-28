/**
 * CLI Tool: Grant Delegated Administration Custom Claim via Firebase Admin SDK
 * 
 * Directives:
 * - Admin role carried by a Firebase custom claim minted server-side via the Admin SDK.
 * - Never derived from a client-writable Firestore field, an email domain check, or a hardcoded UID list in client code.
 * 
 * Usage:
 *   npx tsx scripts/grant-admin.ts <USER_UID>
 *   npx tsx scripts/grant-admin.ts <USER_UID> --revoke
 */

import { initializeApp, getApps, applicationDefault } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import * as dotenv from 'dotenv';

dotenv.config();

// Ensure Firebase Admin App is initialized
if (getApps().length === 0) {
  try {
    initializeApp({
      credential: applicationDefault(),
      projectId: process.env.VITE_FIREBASE_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT || 'aegis-journal',
    });
  } catch (err: any) {
    console.error('Failed to initialize Firebase Admin SDK:', err.message);
    process.exit(1);
  }
}

const auth = getAuth();

async function main() {
  const args = process.argv.slice(2);
  const uid = args[0];
  const isRevoke = args.includes('--revoke');

  if (!uid || uid.startsWith('--')) {
    console.error('\nUsage:');
    console.error('  npx tsx scripts/grant-admin.ts <USER_UID>');
    console.error('  npx tsx scripts/grant-admin.ts <USER_UID> --revoke\n');
    console.error('Example:');
    console.error('  npx tsx scripts/grant-admin.ts wjK82Lx91sZp349\n');
    process.exit(1);
  }

  try {
    // 1. Verify user exists in Firebase Auth
    const userRecord = await auth.getUser(uid);
    console.log(`\n[Aegis Security] User located: ${userRecord.email || userRecord.displayName || uid} (${uid})`);

    const newClaims = isRevoke ? { admin: false } : { admin: true };

    // 2. Mint custom claim server-side via Admin SDK
    await auth.setCustomUserClaims(uid, newClaims);

    console.log(`[Aegis Security] Successfully ${isRevoke ? 'REVOKED' : 'GRANTED'} admin custom claim:`);
    console.log(JSON.stringify(newClaims, null, 2));
    console.log('\nNOTE: The authenticated user must refresh their token to receive the new claim.');
    console.log('In the Aegis Trust Center, click "Re-verify Claim" or re-sign-in to take effect immediately.\n');
  } catch (err: any) {
    console.error('\n[Aegis Security Error] Failed to update custom claims:');
    console.error(err.message || err);
    process.exit(1);
  }
}

main();
