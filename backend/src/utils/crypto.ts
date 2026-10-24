import { createHash, createHmac, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { env } from '../config/env.js';

const scrypt = promisify(scryptCallback) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

/**
 * scrypt parameters for hashing the *client-derived* authentication verifier.
 *
 * The browser already ran Argon2id over the account password, so this layer
 * exists to make a stolen database useless on its own rather than to resist a
 * full offline password attack by itself.
 */
const SCRYPT = { N: 32_768, r: 8, p: 1, keyLen: 32, maxmem: 96 * 1024 * 1024 } as const;

export async function hashAuthVerifier(verifier: string): Promise<string> {
  const salt = randomBytes(16);
  const derived = await scrypt(verifier, salt, SCRYPT.keyLen, SCRYPT);
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), derived.toString('base64')].join('$');
}

/** Constant-time verification. Returns false for malformed stored hashes. */
export async function verifyAuthVerifier(verifier: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4] ?? '', 'base64');
  const expected = Buffer.from(parts[5] ?? '', 'base64');
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p) || salt.length === 0 || expected.length === 0) {
    return false;
  }

  const derived = await scrypt(verifier, salt, expected.length, { N, r, p, maxmem: SCRYPT.maxmem });
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

/**
 * Burns a comparable amount of CPU when the account does not exist, so login
 * timing does not disclose whether an email is registered.
 */
export async function dummyVerify(): Promise<void> {
  await scrypt('vaultory-timing-equalizer', 'vaultory-timing-equalizer-salt', SCRYPT.keyLen, SCRYPT);
}

/** Cryptographically secure opaque token (session cookies, email links). */
export function generateToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/**
 * Keyed hash used before persisting any bearer token. Keying with
 * SESSION_SECRET means a leaked database alone cannot be replayed.
 */
export function hashToken(token: string): string {
  return createHmac('sha256', env.SESSION_SECRET).update(token).digest('hex');
}

export function timingSafeEqualString(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/** Stable, non-reversible identifier for rate-limit buckets (keeps PII out of the DB). */
export function rateLimitKey(scope: string, identifier: string): string {
  return `${scope}:${createHash('sha256').update(`${scope}|${identifier}`).digest('hex').slice(0, 32)}`;
}
