import { generateSync } from 'otplib';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { generateOtpAuthUri, generateTotpSecret, verifyTotp } from './totp';

// RFC 6238 SHA-1 secret, with six-digit tokens for the default 30-second period.
const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const OTHER_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const CURRENT_TOKEN = '287082';
const NEXT_TOKEN = '359152';

describe('generateTotpSecret', () => {
  test('returns a base32 secret string', () => {
    const secret = generateTotpSecret();

    expect(typeof secret).toBe('string');
    expect(secret).toMatch(/^[A-Z2-7]+$/);
  });

  test('returns a different secret each call', () => {
    expect(generateTotpSecret()).not.toBe(generateTotpSecret());
  });
});

describe('generateOtpAuthUri', () => {
  test('builds an otpauth uri containing issuer, label and secret', () => {
    const uri = generateOtpAuthUri(SECRET, 'alice');

    expect(uri).toContain('otpauth://totp/');
    expect(uri).toContain('issuer=Umami');
    expect(uri).toContain('alice');
    expect(uri).toContain(`secret=${SECRET}`);
  });
});

describe('verifyTotp', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(59_000);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test('verifies a token generated for the current time step', async () => {
    const token = generateSync({ secret: SECRET });

    expect(token).toBe(CURRENT_TOKEN);
    expect(await verifyTotp(token, SECRET)).toBe(true);
  });

  test('rejects an incorrect token', async () => {
    // One digit differs from the known token at the frozen time.
    expect(await verifyTotp('287083', SECRET)).toBe(false);
  });

  test('rejects a valid token verified against a different secret', async () => {
    const token = generateSync({ secret: SECRET });

    expect(token).toBe(CURRENT_TOKEN);
    expect(generateSync({ secret: OTHER_SECRET })).toBe('503347');
    expect(await verifyTotp(token, OTHER_SECRET)).toBe(false);
  });

  test('switches accepted tokens exactly at a 30-second time-step boundary', async () => {
    vi.setSystemTime(59_999);

    expect(generateSync({ secret: SECRET })).toBe(CURRENT_TOKEN);
    expect(await verifyTotp(CURRENT_TOKEN, SECRET)).toBe(true);
    expect(await verifyTotp(NEXT_TOKEN, SECRET)).toBe(false);

    vi.setSystemTime(60_000);

    expect(generateSync({ secret: SECRET })).toBe(NEXT_TOKEN);
    expect(await verifyTotp(NEXT_TOKEN, SECRET)).toBe(true);
    expect(await verifyTotp(CURRENT_TOKEN, SECRET)).toBe(false);
  });
});
