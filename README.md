# Aegis Journal — Private Financial Reflection Gateway

Aegis Journal is a zero-plaintext financial psychological reflection web application powered by **Google Cloud Run**, **Google Cloud Secret Manager**, **Cloud Firestore**, and **Gemini 3.6 Flash**. 

It enables users to write honest reflections about their financial anxieties, impulse spending, and monetary dilemmas while guaranteeing that no financial account number, credit card, PAN, Aadhaar, IFSC, UPI handle, or personal contact identifier is ever transmitted to an AI model or stored in plaintext in the database.

---

## 1. Zero-Plaintext Security Architecture

```
+-----------------------------------------------------------------------------------+
| Browser Client (Firebase Auth / Google Sign-In Only)                              |
| - Uninhibited reflection typed in memory                                          |
| - Zero API keys in browser bundle                                                 |
+----------------------------------------+------------------------------------------+
                                         |  HTTPS (Bearer ID Token)
                                         v
+-----------------------------------------------------------------------------------+
| Cloud Run Backend (Node.js / Express Server)                                      |
|                                                                                   |
|  [Step 1] Server-Side Deterministic Redaction Gateway                             |
|           • Payment Cards (Luhn algorithm validated) -> [CARD_1]                  |
|           • Indian PAN ([A-Z]{5}[0-9]{4}[A-Z]) -> [PAN_1]                         |
|           • Indian Aadhaar (12 digits / Verhoeff checksum) -> [AADHAAR_1]         |
|           • Indian IFSC Code ([A-Z]{4}0[A-Z0-9]{6}) -> [IFSC_1]                   |
|           • UPI VPA (handle@bank) -> [UPI_1]                                      |
|           • Bank Account Numbers (9-18 digits) -> [ACCT_1]                        |
|           • Contact Emails & Phones -> [EMAIL_1], [PHONE_1]                       |
|           • User-Declared Aliases (Employers, Banks) -> [ALIAS_1]                 |
|           • Currency amounts ($1,500, Rs 12,000) & sentiment preserved           |
|                                                                                   |
|  [Step 2] Cloud Firestore Write (Database ID: aegis-journal-dbid)                 |
|           • Canonical stored record is CANONICAL REDACTED FORM ONLY               |
|           • Path: users/{uid}/entries/{entryId}                                   |
|           • Timestamps: serverTimestamp() only                                    |
|           • Audit Log: users/{uid}/auditLogs with {action, ts}                    |
|                                                                                   |
|  [Step 3] Resilient Gemini Reflection Ladder (<JOURNAL_DATA> Delimiters)          |
|           • Primary: gemini-3.6-flash                                             |
|           • High-Availability Fallback: gemini-3.1-flash-lite                     |
|           • Dynamic Alias: gemini-flash-latest                                    |
|           • Deep Reasoning: gemini-3.7-flash                                      |
|           • Non-Advisory Guardrail (Never tax/investment/credit advice)           |
+-----------------------------------------------------------------------------------+
```

---

## 2. Environment & Prerequisites

1. **Google Cloud SDK (`gcloud` CLI)** installed and authenticated.
2. **Google Cloud Project** created (e.g. `aegis-journal-prod`).
3. **APIs Enabled**:
   ```bash
   gcloud services enable \
     run.googleapis.com \
     secretmanager.googleapis.com \
     firestore.googleapis.com \
     iam.googleapis.com
   ```

---

## 3. Secret Management Setup (Google Cloud Secret Manager)

Store the Gemini API Key securely in Secret Manager:

```bash
# 1. Create and populate the secret
gcloud secrets create GEMINI_API_KEY --replication-policy="automatic"
echo -n "YOUR_GEMINI_API_KEY" | gcloud secrets versions add GEMINI_API_KEY --data-file=-

# 2. Create a dedicated least-privilege runtime service account
gcloud iam service-accounts create aegis-journal-runtime \
  --display-name="Aegis Journal Runtime Service Account"

# 3. Grant the service account read access ONLY to the secret
gcloud secrets add-iam-policy-binding GEMINI_API_KEY \
  --member="serviceAccount:aegis-journal-runtime@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# 4. Grant Cloud Datastore / Firestore user role
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:aegis-journal-runtime@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/datastore.user"
```

---

## 4. Cloud Firestore Security Rules Configuration

Deploy the following owner-bound, zero-insecure-default rules:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    function isAuthenticated() {
      return request.auth != null;
    }

    function isOwner(userId) {
      return isAuthenticated() && request.auth.uid == userId;
    }

    function hasValidGrant(userId, entryId) {
      let grantPath = /databases/$(database)/documents/users/$(userId)/entries/$(entryId)/grants/$(request.auth.uid);
      return exists(grantPath) &&
             get(grantPath).data.revoked == false &&
             (!('expiresAt' in get(grantPath).data) || get(grantPath).data.expiresAt > request.time);
    }

    match /{document=**} {
      allow read, write: if false;
    }

    match /users/{userId} {
      allow read, write: if isOwner(userId);

      match /profile/{profileId} {
        allow read, write: if isOwner(userId);
      }

      match /entries/{entryId} {
        allow read: if isOwner(userId) || hasValidGrant(userId, entryId);
        allow create, update, delete: if isOwner(userId);

        match /messages/{messageId} {
          allow read: if isOwner(userId) || hasValidGrant(userId, entryId);
          allow write: if isOwner(userId);
        }

        match /grants/{granteeUid} {
          allow read: if isOwner(userId) || (isAuthenticated() && request.auth.uid == granteeUid);
          allow create, update: if isOwner(userId);
          allow delete: if false;
        }
      }

      match /auditLogs/{logId} {
        allow read: if isOwner(userId);
        allow create: if isOwner(userId) &&
                         request.resource.data.keys().hasOnly(['action', 'ts']);
        allow update, delete: if false;
      }
    }
  }
}
```

---

## 5. Google Cloud Run Deployment

Deploy the containerized full-stack application to Cloud Run with Secret Manager bindings:

```bash
# Build and Deploy to Cloud Run
gcloud run deploy aegis-journal \
  --source . \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --service-account aegis-journal-runtime@YOUR_PROJECT_ID.iam.gserviceaccount.com \
  --set-secrets="GEMINI_API_KEY=GEMINI_API_KEY:latest" \
  --port=3000

# Apply Mandatory Challenge Verification Label
gcloud run services update aegis-journal \
  --update-labels=dev-tutorial=cloud-run-ai-challenge \
  --region=us-central1
```

---

## 6. End-to-End Walkthrough Test Scenarios

### Test Case 1: Google Federated Authentication
- **Step 1**: Open application in browser. Observe that only Google Sign-In is presented; no password fields exist.
- **Step 2**: Click "Continue with Google" and complete authentication.
- **Step 3**: Verify redirection into private dashboard with active user avatar and email.

### Test Case 2: Financial Reflection & Server Redaction
- **Step 1**: Navigate to "New Reflection".
- **Step 2**: Enter test reflection:
  > *"I overspent on dining out again, and my ICICI account 004501234567 is down to Rs 12,000. Paid using card 4111 2222 3333 4444."*
- **Step 3**: Click "Reflect & Tokenize".
- **Step 4**: Verify in detail view that:
  - Owner View shows what you typed.
  - "Canonical Record" toggle shows `[ALIAS_1] account [ACCT_1] is down to Rs 12,000. Paid using card [CARD_1]`.
  - Gemini replies with empathetic behavioral reflection and clarifying questions without giving financial advice.

### Test Case 3: Multi-Turn Conversation Thread
- **Step 1**: In the reflection detail view, enter a follow-up reply:
  > *"Why do I feel compelled to buy comforting food after stressful work shifts?"*
- **Step 2**: Click "Send".
- **Step 3**: Observe multi-turn model response exploring psychological root causes.

### Test Case 4: Trust Center Live Invariant Self-Tests
- **Step 1**: Click "Trust Center" in header.
- **Step 2**: Under "1. Live Redaction Inspector", input custom financial identifiers and click "Execute Live Server Audit". Confirm tokenization.
- **Step 3**: Under "2. Isolation Self-Test", click "Execute Live Foreign Tenant Read". Confirm verbatim `permission-denied` rejection from Firestore.
- **Step 4**: Under "3. Prompt-Injection Neutralizer", click "Launch Adversarial Injection Attack". Confirm model neutralizes system prompt override attempt.
- **Step 5**: Under "4. Key Custody Statement", verify 0 client key leakage assertion.


## 7. Deployed Project URL 

Deployed URL for the Aegis Journal Application:
 https://aegis-journal-v1.ai.studio

