import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../../db/prisma.js';
import { csrfGuard, getAuth, requireAuth, requireVerifiedEmail } from '../../middleware/auth.js';
import { dbRateLimit, userIdentifier } from '../../middleware/rateLimit.js';
import { recordActivity } from '../../services/activity.js';
import { clearSessionCookie } from '../../services/session.js';
import { verifyAuthVerifier } from '../../utils/crypto.js';
import { toUserDto } from '../../utils/dto.js';
import { ApiError } from '../../utils/http.js';
import { parseBody, parseIdParam } from '../../utils/request.js';
import { nameSchema } from '../../utils/validation.js';
import { deleteAccountSchema } from '../auth/schemas.js';

const updateSettingsSchema = z
  .object({
    name: nameSchema.nullish(),
    /** 0 disables the inactivity timer; the key still clears on manual lock. */
    autoLockMinutes: z.number().int().min(0).max(480).optional(),
    // 'system' is the schema default - without it a user who picked a theme
    // could never switch back.
    theme: z.enum(['light', 'dark', 'system']).optional(),
  })
  .refine((value) => Object.keys(value).length > 0, { error: 'Nothing to update.' });

export const settingsRouter = Router();

settingsRouter.use(requireAuth, csrfGuard);

settingsRouter.get('/', async (req, res) => {
  const { user } = getAuth(req);

  const [secretCount, folderCount, favoriteCount, sessionCount, strandedSecrets] = await Promise.all([
    prisma.secret.count({ where: { userId: user.id, deletedAt: null } }),
    prisma.folder.count({ where: { userId: user.id } }),
    prisma.secret.count({ where: { userId: user.id, isFavorite: true, deletedAt: null } }),
    prisma.session.count({ where: { userId: user.id, revokedAt: null, expiresAt: { gt: new Date() } } }),
    prisma.secret.count({ where: { userId: user.id, keyVersion: { lt: user.vaultKeyVersion } } }),
  ]);

  res.json({
    user: toUserDto(user),
    stats: { secretCount, folderCount, favoriteCount, sessionCount, strandedSecrets },
    security: {
      encryption: 'AES-256-GCM (browser)',
      keyDerivation: `${user.kdfAlgorithm} m=${user.kdfMemoryKiB}KiB t=${user.kdfIterations} p=${user.kdfParallelism}`,
      /** Honest statement of the recovery model - see docs/encryption.md. */
      recovery: 'password-only',
    },
  });
});

settingsRouter.patch('/', async (req, res) => {
  const { user } = getAuth(req);
  const body = parseBody(updateSettingsSchema, req);

  const updated = await prisma.user.update({
    where: { id: user.id },
    data: {
      ...(body.name !== undefined ? { name: body.name ?? null } : {}),
      ...(body.autoLockMinutes !== undefined ? { autoLockMinutes: body.autoLockMinutes } : {}),
      ...(body.theme !== undefined ? { theme: body.theme } : {}),
    },
  });

  await recordActivity({ userId: user.id, type: 'SETTINGS_UPDATED', targetType: 'account', req });
  res.json({ user: toUserDto(updated) });
});

export const accountRouter = Router();

accountRouter.use(requireAuth, csrfGuard);

const shareKeySchema = z.object({
  /** Raw uncompressed P-256 point, 65 bytes. */
  sharePublicKey: z.string().min(80).max(128),
  sharePrivateKeyWrapped: z.object({
    nonce: z.string().min(16).max(32),
    ciphertext: z.string().min(1).max(8_192),
  }),
});

/**
 * Publishes the user's ECDH share key. Called lazily by the client the first
 * time it finds `sharePublicKey` missing - the private half arrives already
 * wrapped under the vault key, so the payload is ciphertext-only.
 */
accountRouter.put('/share-key', requireVerifiedEmail, async (req, res) => {
  const { user } = getAuth(req);
  const body = parseBody(shareKeySchema, req);

  const updated = await prisma.user.update({
    where: { id: user.id },
    data: {
      sharePublicKey: body.sharePublicKey,
      sharePrivateKeyWrapped: body.sharePrivateKeyWrapped,
    },
  });
  res.json({ sharePublicKey: updated.sharePublicKey });
});

// --- Passkey (WebAuthn PRF) vault unlock ----------------------------------
// Not a login factor: rows hold the vault key AES-GCM wrapped under the
// authenticator's PRF output. The session cookie still gates access; the
// assertion itself is verified by the authenticator, not the server.

const enrollPasskeySchema = z.object({
  credentialId: z.string().min(16).max(512),
  name: z.string().trim().min(1).max(60).optional(),
  prfSalt: z.string().min(40).max(64),
  wrappedVaultKey: z.object({
    nonce: z.string().min(16).max(32),
    ciphertext: z.string().min(1).max(8_192),
  }),
});

accountRouter.get('/passkeys', requireVerifiedEmail, async (req, res) => {
  const { user } = getAuth(req);
  const passkeys = await prisma.passkey.findMany({
    where: { userId: user.id },
    orderBy: { createdAt: 'asc' },
    select: { id: true, credentialId: true, name: true, prfSalt: true, wrappedVaultKey: true, createdAt: true },
  });
  res.json({
    passkeys: passkeys.map((p) => ({
      id: p.id,
      credentialId: p.credentialId,
      name: p.name,
      prfSalt: p.prfSalt,
      wrappedVaultKey: p.wrappedVaultKey,
      createdAt: p.createdAt.toISOString(),
    })),
  });
});

accountRouter.post('/passkeys', requireVerifiedEmail, async (req, res) => {
  const { user } = getAuth(req);
  const body = parseBody(enrollPasskeySchema, req);

  const existing = await prisma.passkey.findUnique({ where: { credentialId: body.credentialId } });
  if (existing) throw new ApiError(409, 'exists', 'That passkey is already registered.');

  const count = await prisma.passkey.count({ where: { userId: user.id } });
  if (count >= 10) throw new ApiError(429, 'too_many', 'Remove a passkey before adding another.');

  const passkey = await prisma.passkey.create({
    data: {
      userId: user.id,
      credentialId: body.credentialId,
      name: body.name ?? null,
      prfSalt: body.prfSalt,
      wrappedVaultKey: body.wrappedVaultKey,
    },
  });
  res.status(201).json({ id: passkey.id });
});

accountRouter.delete('/passkeys/:id', requireVerifiedEmail, async (req, res) => {
  const { user } = getAuth(req);
  const passkey = await prisma.passkey.findUnique({ where: { id: parseIdParam(req) } });
  if (!passkey || passkey.userId !== user.id) throw new ApiError(404, 'not_found', 'Passkey not found.');
  await prisma.passkey.delete({ where: { id: passkey.id } });
  res.json({ deleted: true });
});

// Verifies the password - budget it so a stolen session cannot brute-force.
accountRouter.delete(
  '/',
  dbRateLimit({ scope: 'delete-account', limit: 5, windowMs: 60 * 60 * 1000, identifier: userIdentifier }),
  async (req, res) => {
  const { user } = getAuth(req);
  const body = parseBody(deleteAccountSchema, req);

  const valid = await verifyAuthVerifier(body.authVerifier, user.authHash);
  if (!valid) throw ApiError.unauthorized('Your password is incorrect.');

  // Cascades to sessions, folders, secrets, versions and activity.
  await prisma.user.delete({ where: { id: user.id } });
  clearSessionCookie(res);

  res.json({ deleted: true });
  },
);
