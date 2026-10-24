import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { env } from '../config/env.js';
import { timingSafeEqualString } from './crypto.js';
import { ApiError } from './http.js';

/**
 * RFC 6238 TOTP (HMAC-SHA1, 30-second step, 6 digits) for account-level 2FA.
 * Secrets are generated server-side, wrapped at rest under a key derived from
 * VAULT_WRAP_SECRET, and only returned once during setup so the user can add
 * them to an authenticator app.
 */

const STEP_SECONDS = 30;
const DIGITS = 6;
const SECRET_BYTES = 20; // 160 bits - the RFC 4226 recommended minimum

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(data: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(encoded: string): Buffer {
  const clean = encoded.replace(/=+$/, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const idx = B32_ALPHABET.indexOf(char);
    if (idx === -1) throw new ApiError(400, 'invalid_totp', 'Malformed TOTP secret.');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** HOTP moving factor -> 6-digit code (RFC 4226 dynamic truncation). */
export function hotp(secret: Buffer, counter: bigint | number): string {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', secret).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    (hmac[offset + 1]! << 16) |
    (hmac[offset + 2]! << 8) |
    hmac[offset + 3]!;
  return (code % 10 ** DIGITS).toString().padStart(DIGITS, '0');
}

export function totpAt(secret: Buffer, timeMs: number): string {
  return hotp(secret, Math.floor(timeMs / 1000 / STEP_SECONDS));
}

/** Accepts the current step and one step either side for clock drift. */
export function verifyTotp(secret: Buffer, code: string, timeMs = Date.now()): boolean {
  if (!/^\d{6}$/.test(code)) return false;
  const step = Math.floor(timeMs / 1000 / STEP_SECONDS);
  for (const drift of [-1, 0, 1]) {
    if (hotp(secret, step + drift) === code) return true;
  }
  return false;
}

/** otpauth:// URI for QR-code enrolment in authenticator apps. */
export function otpauthUrl(secretB32: string, email: string): string {
  const label = encodeURIComponent(`Vaultory:${email}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=Vaultory&algorithm=SHA1&digits=6&period=30`;
}

export function generateTotpSecret(): { raw: Buffer; base32: string } {
  const raw = randomBytes(SECRET_BYTES);
  return { raw, base32: base32Encode(raw) };
}

// --- at-rest storage: AES-256-GCM under a server-only key -------------------

const WRAP_AAD = Buffer.from('vaultory|totp|v1', 'utf8');

function wrapKey(): Buffer {
  return Buffer.from(hkdfSync('sha256', env.VAULT_WRAP_SECRET, 'vaultory-totp', 'wrap-key', 32));
}

export function wrapTotpSecret(secret: Buffer): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', wrapKey(), nonce);
  cipher.setAAD(WRAP_AAD);
  const ct = Buffer.concat([cipher.update(secret), cipher.final(), cipher.getAuthTag()]);
  return `t1.${nonce.toString('base64')}.${ct.toString('base64')}`;
}

export function unwrapTotpSecret(blob: string): Buffer {
  const parts = blob.split('.');
  if (parts.length !== 3 || parts[0] !== 't1') {
    throw new ApiError(400, 'invalid_totp', 'Unrecognised TOTP secret format.');
  }
  const decipher = createDecipheriv('aes-256-gcm', wrapKey(), Buffer.from(parts[1]!, 'base64'));
  decipher.setAAD(WRAP_AAD);
  const ct = Buffer.from(parts[2]!, 'base64');
  decipher.setAuthTag(ct.subarray(-16));
  try {
    return Buffer.concat([decipher.update(ct.subarray(0, -16)), decipher.final()]);
  } catch {
    throw new ApiError(400, 'invalid_totp', 'The stored TOTP secret could not be decrypted.');
  }
}

/**
 * Stateless, short-lived proof that the password half of login succeeded.
 * The MFA step is bound to a user id + expiry and signed with SESSION_SECRET -
 * a forged or replayed token cannot mint a session.
 */
export function signMfaToken(userId: string, ttlMs = 5 * 60 * 1000): string {
  const payload = `${userId}.${Date.now() + ttlMs}.${randomBytes(8).toString('base64url')}`;
  const sig = createHmac('sha256', env.SESSION_SECRET).update(`mfa|${payload}`).digest('base64url');
  return `${payload}.${sig}`;
}

export function verifyMfaToken(token: string): string | null {
  const parts = token.split('.');
  if (parts.length < 4) return null;
  const payload = parts.slice(0, -1).join('.');
  const expected = createHmac('sha256', env.SESSION_SECRET).update(`mfa|${payload}`).digest('base64url');
  if (!timingSafeEqualString(expected, parts[parts.length - 1] ?? '')) return null;
  const [userId, exp] = payload.split('.');
  if (!userId || !exp || Number(exp) <= Date.now()) return null;
  return userId;
}
