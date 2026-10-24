import { createCipheriv, createDecipheriv, createECDH, hkdfSync, randomBytes, type ECDH } from 'node:crypto';
import { env } from '../config/env.js';
import { ApiError } from './http.js';

/**
 * Vault-key escrow.
 *
 * The vault key is additionally wrapped under the *server's* P-256 key so that
 * an email-verified password reset can recover it without a recovery phrase.
 * Clients escrow the key at signup ("s1.<ephPub>.<nonce>.<ct>") and the server
 * hands it back at reset re-encrypted to the browser's ephemeral key
 * ("s1.<nonce>.<ct>"). The raw key never travels the wire, but the server
 * *can* unwrap it in memory - a documented trade-off that makes reset lossless.
 *
 * Both directions use ECDH(P-256) -> the raw 32-byte shared secret directly as
 * an AES-256-GCM key, which is exactly what WebCrypto `deriveKey` produces, so
 * Node and the browser interoperate without an extra KDF layer.
 */

const AAD = Buffer.from('vaultory|escrow|v1', 'utf8');
const NONCE_BYTES = 12;

let cached: ECDH | undefined;

function serverEcdh(): ECDH {
  if (cached) return cached;
  const ecdh = createECDH('prime256v1');
  // Deterministic private scalar from the env secret. A P-256 scalar must be
  // < group order; the counter branch makes invalid draws practically
  // impossible but keeps the derivation total.
  for (let i = 0; ; i += 1) {
    const scalar = hkdfSync('sha256', env.VAULT_WRAP_SECRET, 'vaultory-escrow', `ecdh-p256:${i}`, 32);
    try {
      ecdh.setPrivateKey(Buffer.from(scalar));
      cached = ecdh;
      return ecdh;
    } catch {
      continue;
    }
  }
}

/** Raw 65-byte uncompressed P-256 public point, base64 encoded for clients. */
export function serverEscrowPublicKey(): string {
  return serverEcdh().getPublicKey(undefined, 'uncompressed').toString('base64');
}

function aeadEncrypt(key: Buffer, plaintext: Buffer): { nonce: string; ciphertext: string } {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(AAD);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { nonce: nonce.toString('base64'), ciphertext: ciphertext.toString('base64') };
}

function aeadDecrypt(key: Buffer, nonce: Buffer, ciphertext: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(AAD);
  const tag = ciphertext.subarray(ciphertext.length - 16);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext.subarray(0, -16)), decipher.final()]);
  } catch {
    throw new ApiError(400, 'invalid_escrow', 'The stored vault-key escrow could not be decrypted.');
  }
}

/**
 * Unwraps the blob the browser produced at signup:
 * `s1.<base64 ephPub 65B>.<base64 nonce>.<base64 ct>` -> raw vault key.
 */
export function unwrapEscrowedVaultKey(blob: string): Buffer {
  const parts = blob.split('.');
  if (parts.length !== 4 || parts[0] !== 's1') {
    throw new ApiError(400, 'invalid_escrow', 'Unrecognised escrowed vault key format.');
  }
  const ephPub = Buffer.from(parts[1] ?? '', 'base64');
  const nonce = Buffer.from(parts[2] ?? '', 'base64');
  const ciphertext = Buffer.from(parts[3] ?? '', 'base64');
  if (ephPub.length !== 65 || nonce.length !== NONCE_BYTES) {
    throw new ApiError(400, 'invalid_escrow', 'Malformed escrowed vault key.');
  }
  const shared = computeShared(ephPub);
  return aeadDecrypt(shared, nonce, ciphertext);
}

/** computeSecret throws an OpenSSL error on a malformed point - map to 400. */
function computeShared(publicPoint: Buffer): Buffer {
  try {
    return serverEcdh().computeSecret(publicPoint);
  } catch {
    throw new ApiError(400, 'invalid_request', 'The supplied ECDH public key is not a valid P-256 point.');
  }
}

/**
 * Re-encrypts the raw vault key to the browser's ephemeral reset key:
 * returns `s1.<base64 nonce>.<base64 ct>` (the client holds the private half).
 */
export function wrapVaultKeyForClient(vaultKeyRaw: Buffer, clientPublicKeyB64: string): string {
  const clientPub = Buffer.from(clientPublicKeyB64, 'base64');
  if (clientPub.length !== 65) {
    throw new ApiError(400, 'invalid_request', 'Client public key must be a raw P-256 point.');
  }
  const shared = computeShared(clientPub);
  const { nonce, ciphertext } = aeadEncrypt(shared, vaultKeyRaw);
  return `s1.${nonce}.${ciphertext}`;
}
