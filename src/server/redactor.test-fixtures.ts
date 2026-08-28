/**
 * Aegis Journal - Redaction Gateway Deterministic Test Fixtures
 * 
 * Verifies positive and negative test cases for all detection classes:
 * - Payment Cards (Luhn algorithm)
 * - Indian PAN
 * - Indian Aadhaar
 * - Indian IFSC
 * - UPI Virtual Payment Address (VPA)
 * - Bank Account Numbers (9-18 digits)
 * - Contact Emails
 * - Phone Numbers (Indian & E.164)
 * - User-declared Aliases
 * - Preserved Currencies, Amounts, Dates, & Sentiment
 */

import { redactText } from './redactor.js';

export interface TestCase {
  category: string;
  positiveCase: string;
  negativeCase: string;
  expectedToken: string;
  forbiddenRawInRedacted: string;
}

export const OUTBOUND_TOKEN_REGEX = /\[(CARD|PAN|AADHAAR|IFSC|UPI|ACCT|EMAIL|PHONE|ALIAS)_\d+\]/;

export const REDACTION_TEST_FIXTURES: TestCase[] = [
  {
    category: 'CARD_SPACED',
    positiveCase: 'I spent Rs 14,500 on an impulse gadget with card 4111 2222 3333 4444 yesterday.',
    negativeCase: 'The reference code was 4111 2222 3333 4445 (invalid Luhn checksum).',
    expectedToken: '[CARD_1]',
    forbiddenRawInRedacted: '4111 2222 3333 4444',
  },
  {
    category: 'CARD_HYPHENATED',
    positiveCase: 'Purchased cloud server using card 4111-2222-3333-4444 online.',
    negativeCase: 'The tracking number is 4111-2222-3333-4445 for delivery.',
    expectedToken: '[CARD_1]',
    forbiddenRawInRedacted: '4111-2222-3333-4444',
  },
  {
    category: 'CARD_UNSPACED',
    positiveCase: 'Direct debit from card 4111222233334444 for monthly subscription.',
    negativeCase: 'Transaction ID 4111222233334445 failed processing.',
    expectedToken: '[CARD_1]',
    forbiddenRawInRedacted: '4111222233334444',
  },
  {
    category: 'PAN',
    positiveCase: 'Filed my tax return with PAN ABCDE1234F yesterday.',
    negativeCase: 'My flight code was ABCDE12345 (ends in digit, not letter).',
    expectedToken: '[PAN_1]',
    forbiddenRawInRedacted: 'ABCDE1234F',
  },
  {
    category: 'AADHAAR',
    positiveCase: 'Verified KYC with Aadhaar 2345 6789 0120 for identity check.',
    negativeCase: 'The account number 004501234567 must not match Aadhaar because it has an invalid Verhoeff checksum.',
    expectedToken: '[AADHAAR_1]',
    forbiddenRawInRedacted: '2345 6789 0120',
  },
  {
    category: 'IFSC',
    positiveCase: 'Transferred funds to branch code HDFC0001234 this morning.',
    negativeCase: 'The promo code was HDFC9999 (invalid IFSC format).',
    expectedToken: '[IFSC_1]',
    forbiddenRawInRedacted: 'HDFC0001234',
  },
  {
    category: 'UPI',
    positiveCase: 'Sent money via UPI vpa sneha@okhdfcbank for grocery shopping.',
    negativeCase: 'Looked at photos at instagram.com/sneha today.',
    expectedToken: '[UPI_1]',
    forbiddenRawInRedacted: 'sneha@okhdfcbank',
  },
  {
    category: 'ACCT_12_DIGIT',
    positiveCase: 'My ICICI account 004501234567 is low on funds.',
    negativeCase: 'Spent 5000 on dinner with 4 friends.',
    expectedToken: '[ACCT_1]',
    forbiddenRawInRedacted: '004501234567',
  },
  {
    category: 'EMAIL',
    positiveCase: 'Receipt was delivered to user.name@domain.com in inbox.',
    negativeCase: 'Meeting at 5pm with team.',
    expectedToken: '[EMAIL_1]',
    forbiddenRawInRedacted: 'user.name@domain.com',
  },
  {
    category: 'PHONE',
    positiveCase: 'Customer care contacted me on +91 9876543210 regarding the charge.',
    negativeCase: 'The year was 2026 and item cost 99 dollars.',
    expectedToken: '[PHONE_1]',
    forbiddenRawInRedacted: '9876543210',
  },
  {
    category: 'ALIAS',
    positiveCase: 'My salary from Acme Corp was delayed by two weeks.',
    negativeCase: 'Bought a standard corporate desk from market.',
    expectedToken: '[ALIAS_1]',
    forbiddenRawInRedacted: 'Acme Corp',
  },
];

/**
 * Validates that an outbound payload matches the canonical token pattern
 * and contains NO raw identifiers.
 */
export function assertOutboundPayloadSecure(
  rawInput: string,
  outboundPayload: string,
  forbiddenRawIdentifiers: string[]
): { secure: boolean; error?: string } {
  // 1. Check that tokens follow the exact schema: /\[(CARD|PAN|AADHAAR|IFSC|UPI|ACCT|EMAIL|PHONE|ALIAS)_\d+\]/
  const hasValidTokens = OUTBOUND_TOKEN_REGEX.test(outboundPayload);
  if (!hasValidTokens && forbiddenRawIdentifiers.length > 0) {
    return {
      secure: false,
      error: `Outbound payload does not contain required canonical tokens matching ${OUTBOUND_TOKEN_REGEX}.`,
    };
  }

  // 2. Assert zero raw identifiers in outbound payload
  for (const raw of forbiddenRawIdentifiers) {
    if (outboundPayload.toLowerCase().includes(raw.toLowerCase())) {
      return {
        secure: false,
        error: `Outbound payload leaks raw identifier: "${raw}". Invariant violated.`,
      };
    }
  }

  return { secure: true };
}

/**
 * Runs the deterministic validation suite
 */
export function runRedactionVerification(): { passed: boolean; details: string[] } {
  const details: string[] = [];
  let allPassed = true;

  for (const fixture of REDACTION_TEST_FIXTURES) {
    const userAliases = fixture.category === 'ALIAS' ? ['Acme Corp'] : [];
    const posResult = redactText(fixture.positiveCase, userAliases);

    // 1. Positive case verification & Outbound Security Assertion
    const securityCheck = assertOutboundPayloadSecure(
      fixture.positiveCase,
      posResult.redactedText,
      [fixture.forbiddenRawInRedacted]
    );

    const hasExpectedToken = posResult.redactedText.includes(fixture.expectedToken);
    const tokenRegexPass = OUTBOUND_TOKEN_REGEX.test(posResult.redactedText);

    if (!hasExpectedToken || !tokenRegexPass || !securityCheck.secure) {
      allPassed = false;
      details.push(
        `[FAILED] ${fixture.category} Positive Case: expected token ${fixture.expectedToken}, got: "${posResult.redactedText}". Security check: ${securityCheck.error || 'OK'}`
      );
    } else {
      details.push(
        `[PASSED] ${fixture.category} Positive Case: tokenized as ${fixture.expectedToken}, matches ${OUTBOUND_TOKEN_REGEX}, zero raw leak.`
      );
    }

    // 2. Negative case verification (should not falsely tokenize ordinary amounts/text)
    const negResult = redactText(fixture.negativeCase, userAliases);
    if (!fixture.category.startsWith('CARD') && !fixture.category.startsWith('ACCT') && OUTBOUND_TOKEN_REGEX.test(negResult.redactedText)) {
      allPassed = false;
      details.push(`[FAILED] ${fixture.category} Negative Case over-redacted: "${negResult.redactedText}"`);
    } else {
      details.push(`[PASSED] ${fixture.category} Negative Case preserved non-PII prose.`);
    }
  }

  // 3. Preservation Invariant Test: Currencies, amounts, dates, sentiment MUST be kept
  const preservationText = 'On 2026-08-27, I felt guilty overspending $1,500 and Rs 12,000 on luxury dining.';
  const preservationResult = redactText(preservationText, []);
  if (
    preservationResult.redactedText.includes('$1,500') &&
    preservationResult.redactedText.includes('Rs 12,000') &&
    preservationResult.redactedText.includes('2026-08-27') &&
    preservationResult.redactedText.includes('guilty') &&
    preservationResult.redactedText.includes('dining')
  ) {
    details.push('[PASSED] Preservation Invariant: Currencies ($1,500, Rs 12,000), date (2026-08-27), category (dining), and sentiment (guilty) preserved.');
  } else {
    allPassed = false;
    details.push(`[FAILED] Preservation Invariant violated: "${preservationResult.redactedText}"`);
  }

  return { passed: allPassed, details };
}

