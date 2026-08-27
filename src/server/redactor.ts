/**
 * Aegis Journal - Server-Side Deterministic PII & Financial Redaction Gateway
 * 
 * Tokenizes sensitive financial and personal identifiers before transmission
 * to external models and before persistence to Cloud Firestore.
 * 
 * Invariants:
 * 1. Token map exists ONLY in request-scoped memory.
 * 2. Deterministic matchers with checksums (Luhn for cards, Verhoeff for Aadhaar).
 * 3. Currencies, amounts, dates, categories, and sentiment words are preserved.
 */

export interface RedactionResult {
  redactedText: string;
  tokenMap: Record<string, string>;
  redactionCounts: Record<string, number>;
  detectedCategories: string[];
}

// Verhoeff algorithm multiplication table for Aadhaar validation
const verhoeffD = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
];

// Verhoeff permutation table
const verhoeffP = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
];

export function validateVerhoeff(numStr: string): boolean {
  if (!/^\d{12}$/.test(numStr)) return false;
  let c = 0;
  const invertedArray = numStr.split('').map(Number).reverse();
  for (let i = 0; i < invertedArray.length; i++) {
    c = verhoeffD[c][verhoeffP[i % 8][invertedArray[i]]];
  }
  return c === 0;
}

export function validateLuhn(cardStr: string): boolean {
  const clean = cardStr.replace(/\D/g, '');
  if (clean.length < 13 || clean.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = clean.length - 1; i >= 0; i--) {
    let digit = parseInt(clean.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

export function redactText(text: string, userAliases: string[] = []): RedactionResult {
  if (!text || typeof text !== 'string') {
    return {
      redactedText: '',
      tokenMap: {},
      redactionCounts: {},
      detectedCategories: []
    };
  }

  let processed = text;
  const tokenMap: Record<string, string> = {};
  const counts: Record<string, number> = {
    CARD: 0,
    PAN: 0,
    AADHAAR: 0,
    IFSC: 0,
    UPI: 0,
    ACCT: 0,
    EMAIL: 0,
    PHONE: 0,
    ALIAS: 0
  };

  const registerToken = (type: string, rawValue: string): string => {
    // Check if we already tokenized this exact value
    for (const [token, val] of Object.entries(tokenMap)) {
      if (val.toLowerCase() === rawValue.toLowerCase() && token.startsWith(`[${type}_`)) {
        return token;
      }
    }
    counts[type] = (counts[type] || 0) + 1;
    const token = `[${type}_${counts[type]}]`;
    tokenMap[token] = rawValue;
    return token;
  };

  // 1. User-Declared Aliases (e.g., specific employer names, bank names, family members)
  if (Array.isArray(userAliases)) {
    for (const alias of userAliases) {
      if (alias && alias.trim().length > 1) {
        const trimmed = alias.trim();
        const escaped = trimmed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const aliasRegex = new RegExp(`\\b${escaped}\\b`, 'gi');
        processed = processed.replace(aliasRegex, (match) => registerToken('ALIAS', match));
      }
    }
  }

  // 2. Emails (before UPI to avoid collisions)
  const emailRegex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
  processed = processed.replace(emailRegex, (match) => registerToken('EMAIL', match));

  // 3. Indian PAN Card (5 uppercase letters, 4 digits, 1 uppercase letter)
  const panRegex = /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g;
  processed = processed.replace(panRegex, (match) => registerToken('PAN', match));

  // 4. Indian IFSC Code (4 letters, 0, 6 alphanumeric)
  const ifscRegex = /\b[A-Z]{4}0[A-Z0-9]{6}\b/g;
  processed = processed.replace(ifscRegex, (match) => registerToken('IFSC', match));

  // 5. UPI Virtual Payment Address (e.g., user@okhdfcbank, name@paytm, 9876543210@ybl)
  const upiRegex = /\b[a-zA-Z0-9._-]{2,256}@(okaxis|okhdfcbank|oksbi|okicici|paytm|ybl|ibl|axl|upi|apl|fbl|sbi|hdfcbank|icici|kotak|barodampay|rbl|indus)\b/gi;
  processed = processed.replace(upiRegex, (match) => registerToken('UPI', match));

  // 6. Payment Cards (13-19 digits, optionally spaced or hyphenated, verified with Luhn Check)
  const cardCandidateRegex = /\b(?:\d[ -]*?){13,19}\b/g;
  processed = processed.replace(cardCandidateRegex, (match) => {
    const rawDigits = match.replace(/\D/g, '');
    if (validateLuhn(rawDigits)) {
      return registerToken('CARD', match.trim());
    }
    return match;
  });

  // 7. Indian Aadhaar Card (12 digits, checked with Verhoeff algorithm or 12-digit spaced sequence)
  const aadhaarRegex = /\b\d{4}[ -]?\d{4}[ -]?\d{4}\b/g;
  processed = processed.replace(aadhaarRegex, (match) => {
    const raw = match.replace(/\D/g, '');
    if (raw.length === 12 && (validateVerhoeff(raw) || /^[2-9]\d{11}$/.test(raw))) {
      return registerToken('AADHAAR', match.trim());
    }
    return match;
  });

  // 8. Bank Account Numbers (9-18 digit runs preceded by terms like account, acct, A/C, or explicit long sequence)
  const explicitAcctRegex = /(?:\b(?:a\/c|acct|account|acc|savings|current|checking|acc\.?\s*no\.?)\s*(?:is|:|#|-)?\s*)([0-9]{9,18})\b/gi;
  processed = processed.replace(explicitAcctRegex, (match, p1) => {
    const token = registerToken('ACCT', p1);
    return match.replace(p1, token);
  });

  // Also catch isolated 10-18 digit numbers that are NOT dates, amounts (like 500000), or phone numbers
  const standaloneAcctRegex = /\b[0-9]{11,18}\b/g;
  processed = processed.replace(standaloneAcctRegex, (match) => {
    // If not already part of a token
    if (match.length >= 11) {
      return registerToken('ACCT', match);
    }
    return match;
  });

  // 9. Phone numbers (E.164 and Indian 10-digit formats)
  const phoneRegex = /(?:\+91[\s-]?)?[6789]\d{9}\b|\b\+?[1-9]\d{1,2}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
  processed = processed.replace(phoneRegex, (match) => {
    // Avoid redacting pure 4-digit numbers or small amounts
    const digits = match.replace(/\D/g, '');
    if (digits.length >= 10 && digits.length <= 13) {
      return registerToken('PHONE', match.trim());
    }
    return match;
  });

  const detectedCategories = Object.keys(counts).filter((cat) => counts[cat] > 0);

  return {
    redactedText: processed,
    tokenMap,
    redactionCounts: counts,
    detectedCategories
  };
}

/**
 * Rehydrates a redacted text string using the request-scoped token map.
 * Rehydration MUST only occur in response payloads returned to the authenticated owner.
 */
export function rehydrateText(text: string, tokenMap: Record<string, string>): string {
  if (!text || !tokenMap || Object.keys(tokenMap).length === 0) return text;
  let result = text;
  for (const [token, originalVal] of Object.entries(tokenMap)) {
    // Replace all occurrences of token
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    result = result.replace(new RegExp(escaped, 'g'), originalVal);
  }
  return result;
}
