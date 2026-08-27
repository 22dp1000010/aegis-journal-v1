/**
 * Aegis Journal - Unified Server Entrypoint (Express + Vite)
 * 
 * Target: Google Cloud Run & AI Studio Sandbox
 * Host: 0.0.0.0, Port: 3000
 */

import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { redactText, rehydrateText } from './src/server/redactor.js';
import { generateReflectionWithFallback, testPromptInjectionDefense } from './src/server/geminiService.js';
import {
  getAdminFirestore,
  recordAuditEvent,
  verifyFirebaseToken,
  sanitizePayload,
  FieldValue,
} from './src/server/firebaseAdmin.js';

// Extend Express Request to include authenticated user
export interface AuthenticatedRequest extends Request {
  user?: {
    uid: string;
    email?: string;
    name?: string;
    [key: string]: any;
  };
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // 1. Mandatory Top-Level Request Deserialization (Ordering Guarantee)
  app.use(express.json({ limit: '1mb' }));
  app.use(express.urlencoded({ extended: true, limit: '1mb' }));

  // 2. Simple in-memory rate limiting per user (Token-bucket pattern)
  const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
  const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
  const MAX_REQUESTS_PER_WINDOW = 30;

  const rateLimiter = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const uid = req.user?.uid || req.ip || 'anonymous';
    const now = Date.now();
    const userBucket = rateLimitMap.get(uid);

    if (!userBucket || now > userBucket.resetTime) {
      rateLimitMap.set(uid, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
      return next();
    }

    if (userBucket.count >= MAX_REQUESTS_PER_WINDOW) {
      const retryAfter = Math.ceil((userBucket.resetTime - now) / 1000);
      res.setHeader('Retry-After', retryAfter.toString());
      recordAuditEvent(req.user?.uid || 'anonymous', 'rate_limit_tripped').catch(() => {});
      return res.status(429).json({
        error: 'Rate limit exceeded. Please pause before submitting additional reflections.',
        retryAfterSeconds: retryAfter,
      });
    }

    userBucket.count++;
    next();
  };

  // 3. Authentication Verification Middleware
  const requireAuth = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Unauthorized: Missing or invalid Bearer token.',
      });
    }

    const idToken = authHeader.split(' ')[1];
    if (!idToken) {
      return res.status(401).json({ error: 'Unauthorized: Empty token.' });
    }

    try {
      const decoded = await verifyFirebaseToken(idToken);
      if (!decoded || !decoded.uid) {
        return res.status(401).json({ error: 'Unauthorized: Invalid or expired Firebase ID token.' });
      }
      req.user = decoded;
      next();
    } catch (err: any) {
      return res.status(401).json({
        error: 'Unauthorized: Authentication failed.',
        details: err?.message || 'Token verification error',
      });
    }
  };

  // --- API ROUTES FIRST ---

  // Health check endpoint
  app.get('/api/health', (req: Request, res: Response) => {
    res.json({
      status: 'ok',
      service: 'Aegis Journal',
      projectId: 'aegis-journal-prod',
      databaseId: 'aegis-journal-dbid',
      timestamp: new Date().toISOString(),
    });
  });

  // Security Key Custody Verification for Trust Center
  app.get('/api/security/custody', requireAuth, (req: AuthenticatedRequest, res: Response) => {
    const hasKey = !!process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.length > 5;
    const keyPreview = hasKey
      ? `AIzaSy...${process.env.GEMINI_API_KEY!.slice(-4)}`
      : 'NOT_FOUND';

    res.json({
      runtimeEnvironment: 'Google Cloud Run / AI Studio Sandbox',
      serverBoundKey: true,
      clientKeyExposure: false,
      keyConfigured: hasKey,
      keyMask: keyPreview,
      databaseId: 'aegis-journal-dbid',
      isolationModel: 'Owner-bound (users/{uid}/entries/{id})',
      piiRedactionGateway: 'Server-Side Deterministic Checksum Matcher',
      checkedAt: new Date().toISOString(),
    });
  });

  // Prompt Injection Defense Self-Test
  app.post('/api/security/test-injection', requireAuth, rateLimiter, async (req: AuthenticatedRequest, res: Response) => {
    const data = req.body && typeof req.body === 'object' ? req.body : {};
    const adversarialPrompt = typeof data.adversarialPrompt === 'string' ? data.adversarialPrompt.trim() : '';

    if (!adversarialPrompt) {
      return res.status(400).json({ error: 'Adversarial prompt payload is required.' });
    }

    try {
      const result = await testPromptInjectionDefense(adversarialPrompt);
      await recordAuditEvent(req.user!.uid, 'prompt_injection_test_executed');

      res.json({
        success: true,
        adversarialInput: adversarialPrompt,
        neutralized: result.neutralized,
        modelUsed: result.modelUsed,
        reflectionResponse: result.rawResponse,
        defenseMechanism: 'Structured <JOURNAL_DATA> Delimiter Isolation & Strict System Instruction',
        timestamp: new Date().toISOString(),
      });
    } catch (err: any) {
      res.status(500).json({
        error: 'Failed to execute prompt injection test.',
        details: err?.message || 'Server error',
      });
    }
  });

  // Audit event ingestion for client self-tests
  app.post('/api/audit', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    const data = req.body && typeof req.body === 'object' ? req.body : {};
    const action = typeof data.action === 'string' ? data.action.trim() : '';

    if (!action) {
      return res.status(400).json({ error: 'Action string is required.' });
    }

    try {
      await recordAuditEvent(req.user!.uid, action);
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to record audit event.' });
    }
  });

  // GET /api/entries - List all entries for authenticated user
  app.get('/api/entries', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    const uid = req.user!.uid;
    try {
      const firestore = getAdminFirestore();
      const entriesRef = firestore.collection(`users/${uid}/entries`);
      const snapshot = await entriesRef.orderBy('createdAt', 'desc').limit(50).get();

      const entries = snapshot.docs.map((doc) => {
        const data = doc.data();
        return {
          id: doc.id,
          title: data.title || 'Financial Reflection',
          redactedContent: data.redactedContent || '',
          redactionSummary: data.redactionSummary || { counts: {}, categories: [] },
          createdAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : new Date().toISOString(),
          updatedAt: data.updatedAt?.toDate ? data.updatedAt.toDate().toISOString() : new Date().toISOString(),
          messageCount: data.messageCount || 0,
        };
      });

      res.json({ entries });
    } catch (err: any) {
      console.error('[Aegis Journal] Failed to list entries:', err);
      res.status(500).json({
        error: 'Failed to fetch entries from database.',
        details: err?.message || 'Firestore read error',
      });
    }
  });

  // GET /api/entries/:id - Fetch entry details and full message thread
  app.get('/api/entries/:id', requireAuth, async (req: AuthenticatedRequest, res: Response) => {
    const uid = req.user!.uid;
    const entryId = req.params.id;

    if (!entryId) {
      return res.status(400).json({ error: 'Entry ID is required.' });
    }

    try {
      const firestore = getAdminFirestore();
      const entryRef = firestore.doc(`users/${uid}/entries/${entryId}`);
      const entryDoc = await entryRef.get();

      if (!entryDoc.exists) {
        return res.status(404).json({ error: 'Entry not found or access denied.' });
      }

      const entryData = entryDoc.data() || {};

      // Fetch messages subcollection
      const messagesRef = firestore.collection(`users/${uid}/entries/${entryId}/messages`);
      const messagesSnapshot = await messagesRef.orderBy('createdAt', 'asc').get();

      const messages = messagesSnapshot.docs.map((doc) => {
        const mData = doc.data();
        return {
          id: doc.id,
          role: mData.role,
          text: mData.text || '',
          modelUsed: mData.modelUsed,
          createdAt: mData.createdAt?.toDate ? mData.createdAt.toDate().toISOString() : new Date().toISOString(),
        };
      });

      res.json({
        id: entryDoc.id,
        title: entryData.title || 'Financial Reflection',
        redactedContent: entryData.redactedContent || '',
        redactionSummary: entryData.redactionSummary || { counts: {}, categories: [] },
        createdAt: entryData.createdAt?.toDate ? entryData.createdAt.toDate().toISOString() : new Date().toISOString(),
        messages,
      });
    } catch (err: any) {
      console.error('[Aegis Journal] Failed to fetch entry:', err);
      res.status(500).json({
        error: 'Failed to fetch entry details.',
        details: err?.message || 'Database error',
      });
    }
  });

  // POST /api/entries - Create a new reflection entry
  app.post('/api/entries', requireAuth, rateLimiter, async (req: AuthenticatedRequest, res: Response) => {
    const uid = req.user!.uid;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const content = typeof body.content === 'string' ? body.content.trim() : '';
    const title = typeof body.title === 'string' && body.title.trim() ? body.title.trim() : 'Financial Reflection';
    const userAliases = Array.isArray(body.userAliases) ? body.userAliases : [];

    if (!content || content.length < 5) {
      return res.status(400).json({
        error: 'Reflection text is too short. Please provide at least 5 characters.',
      });
    }

    if (content.length > 10000) {
      return res.status(400).json({
        error: 'Reflection text exceeds the 10,000 character limit.',
      });
    }

    try {
      // 1. Server-side Redaction Gateway
      const redactionResult = redactText(content, userAliases);

      // 2. Write canonical REDACTED entry to Firestore under users/{uid}/entries
      const firestore = getAdminFirestore();
      const entriesRef = firestore.collection(`users/${uid}/entries`);

      const entryPayload = sanitizePayload({
        title,
        redactedContent: redactionResult.redactedText,
        redactionSummary: {
          counts: redactionResult.redactionCounts,
          categories: redactionResult.detectedCategories,
        },
        messageCount: 1,
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });

      const entryDoc = await entriesRef.add(entryPayload);

      // 3. Log Audit Events: field names EXACTLY "action" and "ts"
      await recordAuditEvent(uid, 'entry_created');
      if (redactionResult.detectedCategories.length > 0) {
        await recordAuditEvent(uid, 'redaction_executed');
      }

      // 4. Generate AI Reflection with Resilient Model Fallback Ladder
      const geminiResult = await generateReflectionWithFallback(
        redactionResult.redactedText,
        []
      );

      // 5. Store Model Reply in messages subcollection
      const messagesRef = firestore.collection(`users/${uid}/entries/${entryDoc.id}/messages`);
      await messagesRef.add(
        sanitizePayload({
          role: 'model',
          text: geminiResult.reflection,
          modelUsed: geminiResult.modelUsed,
          createdAt: FieldValue.serverTimestamp(),
        })
      );

      await recordAuditEvent(uid, 'model_invoked');

      // 6. Return response to authenticated owner with rehydrated view for display
      res.status(201).json({
        success: true,
        id: entryDoc.id,
        title,
        rehydratedContent: content, // Returned directly to authenticated creator
        redactedContent: redactionResult.redactedText, // Exact form stored in Firestore & sent to model
        redactionSummary: {
          counts: redactionResult.redactionCounts,
          categories: redactionResult.detectedCategories,
        },
        reflection: geminiResult.reflection,
        modelUsed: geminiResult.modelUsed,
        createdAt: new Date().toISOString(),
      });
    } catch (err: any) {
      console.error('[Aegis Journal] Failed to create entry:', err);
      res.status(500).json({
        error: 'Failed to process financial reflection.',
        details: err?.message || 'Unknown processing error',
      });
    }
  });

  // POST /api/entries/:id/messages - Add multi-turn message to an existing reflection
  app.post('/api/entries/:id/messages', requireAuth, rateLimiter, async (req: AuthenticatedRequest, res: Response) => {
    const uid = req.user!.uid;
    const entryId = req.params.id;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const text = typeof body.text === 'string' ? body.text.trim() : '';
    const userAliases = Array.isArray(body.userAliases) ? body.userAliases : [];

    if (!text) {
      return res.status(400).json({ error: 'Message text is required.' });
    }

    try {
      const firestore = getAdminFirestore();
      const entryRef = firestore.doc(`users/${uid}/entries/${entryId}`);
      const entryDoc = await entryRef.get();

      if (!entryDoc.exists) {
        return res.status(404).json({ error: 'Entry not found or access denied.' });
      }

      // 1. Redact message text
      const redactionResult = redactText(text, userAliases);

      // 2. Fetch past conversation history
      const messagesRef = firestore.collection(`users/${uid}/entries/${entryId}/messages`);
      const messagesSnapshot = await messagesRef.orderBy('createdAt', 'asc').get();

      const history: Array<{ role: 'user' | 'model'; text: string }> = [];
      // Include original entry as first context
      const entryData = entryDoc.data() || {};
      if (entryData.redactedContent) {
        history.push({ role: 'user', text: entryData.redactedContent });
      }

      messagesSnapshot.docs.forEach((d) => {
        const m = d.data();
        history.push({
          role: m.role === 'model' ? 'model' : 'user',
          text: m.text || '',
        });
      });

      // 3. Save user's redacted message
      const userMsgDoc = await messagesRef.add(
        sanitizePayload({
          role: 'user',
          text: redactionResult.redactedText,
          redactionSummary: {
            counts: redactionResult.redactionCounts,
            categories: redactionResult.detectedCategories,
          },
          createdAt: FieldValue.serverTimestamp(),
        })
      );

      await recordAuditEvent(uid, 'message_sent');

      // 4. Generate AI Reflection
      const geminiResult = await generateReflectionWithFallback(
        redactionResult.redactedText,
        history
      );

      // 5. Save model response
      const modelMsgDoc = await messagesRef.add(
        sanitizePayload({
          role: 'model',
          text: geminiResult.reflection,
          modelUsed: geminiResult.modelUsed,
          createdAt: FieldValue.serverTimestamp(),
        })
      );

      // Update entry timestamp & count
      await entryRef.update({
        updatedAt: FieldValue.serverTimestamp(),
        messageCount: FieldValue.increment(2),
      });

      await recordAuditEvent(uid, 'model_invoked');

      res.status(201).json({
        success: true,
        userMessage: {
          id: userMsgDoc.id,
          role: 'user',
          text: redactionResult.redactedText,
          rehydratedText: text,
          createdAt: new Date().toISOString(),
        },
        modelMessage: {
          id: modelMsgDoc.id,
          role: 'model',
          text: geminiResult.reflection,
          modelUsed: geminiResult.modelUsed,
          createdAt: new Date().toISOString(),
        },
      });
    } catch (err: any) {
      console.error('[Aegis Journal] Failed to add message:', err);
      res.status(500).json({
        error: 'Failed to process message.',
        details: err?.message || 'Processing error',
      });
    }
  });

  // --- VITE MIDDLEWARE (SPA & STATIC ASSETS) ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Aegis Journal] Server active on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[Aegis Journal] Server failed to start:', err);
  process.exit(1);
});
