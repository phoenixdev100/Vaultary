import { describe, expect, it } from 'vitest';
import {
  generateToken,
  hashAuthVerifier,
  hashToken,
  rateLimitKey,
  timingSafeEqualString,
  verifyAuthVerifier,
} from '../src/utils/crypto.js';

describe('auth verifier hashing', () => {
  it('round-trips a verifier through hash + verify', async () => {
    const verifier = generateToken(32);
    const stored = await hashAuthVerifier(verifier);
    await expect(verifyAuthVerifier(verifier, stored)).resolves.toBe(true);
  });

  it('rejects a different verifier', async () => {
    const stored = await hashAuthVerifier(generateToken(32));
    await expect(verifyAuthVerifier(generateToken(32), stored)).resolves.toBe(false);
  });

  it('produces a salted hash that never contains the verifier', async () => {
    const verifier = generateToken(32);
    const stored = await hashAuthVerifier(verifier);
    const [algorithm, n, r, p, salt, derived] = stored.split('$');

    expect(algorithm).toBe('scrypt');
    expect(Number(n)).toBeGreaterThan(0);
    expect(Number(r)).toBeGreaterThan(0);
    expect(Number(p)).toBeGreaterThan(0);
    expect(salt).toBeTruthy();
    expect(derived).toBeTruthy();
    expect(stored).not.toContain(verifier);
  });

  it('re-salts every call (same verifier, different hash)', async () => {
    const verifier = generateToken(32);
    const first = await hashAuthVerifier(verifier);
    const second = await hashAuthVerifier(verifier);
    expect(first).not.toBe(second);
  });

  it('rejects malformed stored hashes without throwing', async () => {
    await expect(verifyAuthVerifier('anything', 'not-a-hash')).resolves.toBe(false);
    await expect(verifyAuthVerifier('anything', 'scrypt$abc')).resolves.toBe(false);
  });
});

describe('token utilities', () => {
  it('generates unique opaque tokens', () => {
    const tokens = new Set(Array.from({ length: 50 }, () => generateToken()));
    expect(tokens.size).toBe(50);
  });

  it('hashes tokens deterministically (needed for session lookup)', () => {
    const token = generateToken();
    expect(hashToken(token)).toBe(hashToken(token));
    expect(hashToken(token)).not.toBe(token);
  });

  it('compares strings in constant time and rejects length mismatches', () => {
    expect(timingSafeEqualString('abc', 'abc')).toBe(true);
    expect(timingSafeEqualString('abc', 'abd')).toBe(false);
    expect(timingSafeEqualString('abc', 'abcd')).toBe(false);
  });

  it('derives stable, scoped rate-limit keys without storing identifiers', () => {
    const a = rateLimitKey('login', 'user@example.com|127.0.0.1');
    const b = rateLimitKey('login', 'user@example.com|127.0.0.1');
    const otherScope = rateLimitKey('signup', 'user@example.com|127.0.0.1');

    expect(a).toBe(b);
    expect(a).not.toBe(otherScope);
    expect(a.startsWith('login:')).toBe(true);
    expect(a).not.toContain('user@example.com');
  });
});
