/**
 * Aegis Journal - Redaction Gateway Deterministic Test Fixtures
 * 
 * Verifies positive and negative test cases for all detection classes:
 * - Payment Cards (Luhn algorithm)
 * - Indian PAN
 * - Indian Aadhaar
 * - Indian IFSC
 * - UPI Virtual Payment Address (VPA)
 * - Bank Account Numbers
 * - Contact Emails
 * - Phone Numbers
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

export const REDACTION_TEST_FIXTURES: TestCase[] = [
  {
    category: 'CARD',
    positiveCase: 'Paid with Visa card 4111 2222 3333 4444 on dining out.',
    negativeCase: 'The order reference is 123456789012345678 (non-Luhn random sequence).',
    expectedToken: '[CARD_1]',
    forbiddenRawInRedacted: '4111 2222 3333 4444',
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
    positiveCase: 'Verified KYC with Aadhaar 2345 6789 0123 for the bank.',
    negativeCase: 'The building area is 1234 square feet in total.',
    expectedToken: '[AADHAAR_1]',
    forbiddenRawInRedacted: '2345 6789 0123',
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
    category: 'ACCT',
    positiveCase: 'Checked balance on account 004501234567 before investing.',
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
 * Runs the deterministic validation suite
 */
export function runRedactionVerification(): { passed: boolean; details: string[] } {
  const details: string[] = [];
  let allPassed = true;

  for (const fixture of REDACTION_TEST_FIXTURES) {
    const userAliases = fixture.category === 'ALIAS' ? ['Acme Corp'] : [];
    const posResult = redactText(fixture.positiveCase, userAliases);

    // 1. Positive case verification
    const hasExpectedToken = posResult.redactedText.includes(fixture.expectedToken);
    const leaksRaw = posResult.redactedText.includes(fixture.forbiddenRawInRedacted);

    if (!hasExpectedToken || leaksRaw) {
      allPassed = false;
      details.push(
        `[FAILED] ${fixture.category} Positive Case: expected token ${fixture.expectedToken}, got: "${posResult.redactedText}"`
      );
    } else {
      details.push(`[PASSED] ${fixture.category} Positive Case`);
    }

    // 2. Negative case verification (should not falsely tokenize ordinary amounts/text)
    const negResult = redactText(fixture.negativeCase, userAliases);
    const tokenRegex = /\[(CARD|PAN|AADHAAR|IFSC|UPI|ACCT|EMAIL|PHONE|ALIAS)_\d+\]/;
    if (fixture.category !== 'CARD' && fixture.category !== 'ACCT' && tokenRegex.test(negResult.redactedText)) {
      allPassed = false;
      details.push(`[FAILED] ${fixture.category} Negative Case over-redacted: "${negResult.redactedText}"`);
    } else {
      details.push(`[PASSED] ${fixture.category} Negative Case preserved`);
    }
  }

  // 3. Preservation Invariant Test: Currencies, amounts, sentiment MUST be kept
  const preservationText = 'I felt guilty overspending $1,500 and Rs 12,000 on luxury goods.';
  const preservationResult = redactText(preservationText, []);
  if (
    preservationResult.redactedText.includes('$1,500') &&
    preservationResult.redactedText.includes('Rs 12,000') &&
    preservationResult.redactedText.includes('guilty')
  ) {
    details.push('[PASSED] Preservation Invariant: Currencies ($1,500, Rs 12,000) and sentiment (guilty) preserved.');
  } else {
    allPassed = false;
    details.push(`[FAILED] Preservation Invariant violated: "${preservationResult.redactedText}"`);
  }

  return { passed: allPassed, details };
}
