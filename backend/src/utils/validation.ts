import { z } from 'zod';
import { SecretCategory } from '../generated/prisma/client.js';

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

/** base64 string with a byte-length budget (prevents oversized payload storage). */
export const base64 = (maxChars: number, label = 'value') =>
  z
    .string()
    .min(4, `${label} is too short`)
    .max(maxChars, `${label} is too large`)
    .regex(BASE64, `${label} must be base64 encoded`);

/** AES-GCM 96-bit nonce: exactly 12 bytes -> 16 base64 characters. */
export const nonceSchema = z
  .string()
  .length(16, 'nonce must be a 12-byte base64 value')
  .regex(BASE64, 'nonce must be base64 encoded');

/** AES-256-GCM ciphertext with appended tag, capped at ~128 KiB of plaintext. */
export const ciphertextSchema = base64(200_000, 'ciphertext');

/** 32-byte client-derived authentication verifier, base64url encoded. */
export const authVerifierSchema = z
  .string()
  .length(43, 'Invalid credentials payload')
  .regex(BASE64URL, 'Invalid credentials payload');

/** Opaque wrapped vault key: "v1.<base64 nonce>.<base64 ciphertext>". */
export const wrappedVaultKeySchema = z
  .string()
  .max(512)
  .regex(/^v1\.[A-Za-z0-9+/]{16}\.[A-Za-z0-9+/]{43,344}={0,2}$/, 'Invalid wrapped vault key');

/**
 * Vault key escrowed to the server's ECDH key:
 * "s1.<base64 ephPub 65B>.<base64 nonce>.<base64 ciphertext>".
 */
export const serverWrappedVaultKeySchema = z
  .string()
  .max(400)
  .regex(
    /^s1\.[A-Za-z0-9+/]{80,96}={0,2}\.[A-Za-z0-9+/]{16}\.[A-Za-z0-9+/]{40,80}={0,2}$/,
    'Invalid escrowed vault key',
  );

/** Raw uncompressed P-256 public point (65 bytes -> 88 base64 chars). */
export const ecdhPublicKeySchema = z
  .string()
  .length(88, 'Client public key must be a raw P-256 point')
  .regex(/^[A-Za-z0-9+/]+={0,2}$/, 'Client public key must be base64 encoded');

/**
 * Client-side KDF parameters. Bounds are enforced so a hostile client cannot
 * register an account with a deliberately weak derivation, and cannot ask other
 * devices to burn unbounded memory when unlocking.
 */
export const kdfSchema = z.object({
  algorithm: z.literal('argon2id'),
  memoryKiB: z.number().int().min(19_456).max(262_144),
  iterations: z.number().int().min(2).max(10),
  parallelism: z.number().int().min(1).max(4),
});

export type KdfParams = z.infer<typeof kdfSchema>;

export const emailSchema = z
  .string()
  .trim()
  .min(3)
  .max(254)
  .transform((value) => value.toLowerCase())
  .pipe(z.email('Enter a valid email address'));

export const nameSchema = z.string().trim().min(1).max(80);

export const titleSchema = z.string().trim().min(1, 'Title is required').max(200);

export const tagsSchema = z.array(z.string().trim().min(1).max(32)).max(12).default([]);

export const categorySchema = z.enum(SecretCategory);

export const idSchema = z.uuid();

export const encryptedPayloadSchema = z.object({
  encVersion: z.literal(1),
  keyVersion: z.number().int().min(1).max(1_000_000),
  nonce: nonceSchema,
  ciphertext: ciphertextSchema,
});
