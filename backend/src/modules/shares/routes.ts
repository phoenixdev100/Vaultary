import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../../db/prisma.js';
import { csrfGuard, getAuth, requireAuth, requireVerifiedEmail } from '../../middleware/auth.js';
import { dbRateLimit, userIdentifier } from '../../middleware/rateLimit.js';
import { recordActivity } from '../../services/activity.js';
import { ApiError } from '../../utils/http.js';
import { parseBody } from '../../utils/request.js';
import { categorySchema, emailSchema } from '../../utils/validation.js';

/**
 * Secure sharing between two Vaultory users.
 *
 * Each user publishes an ECDH P-256 share key (`sharePublicKey`); the
 * matching private key is stored wrapped under their vault key. To share,
 * the sender derives AES-GCM(shared = ephemeral ECDH, recipient share key)
 * client-side and posts only the ciphertext + the ephemeral public point.
 * The server never sees the plaintext payload - same model as secret rows.
 */

const b64 = (len?: number) =>
  z
    .string()
    .min(1)
    .max(16_384)
    .refine((v) => /^[A-Za-z0-9+/]*={0,2}$/.test(v) && v.length % 4 === 0, { error: 'invalid base64' })
    .refine((v) => len === undefined || Buffer.from(v, 'base64').length === len, {
      error: 'invalid length',
    });

const createShareSchema = z.object({
  recipientEmail: emailSchema,
  title: z.string().trim().min(1).max(120),
  category: categorySchema,
  /** Sender's share-scoped public point, 65 bytes raw. */
  senderPublicKey: b64(65).max(128),
  nonce: b64(12).max(32),
  ciphertext: z.string().min(1).max(64_000),
  expiresInDays: z.number().int().min(1).max(90).optional(),
});

export const sharesRouter = Router();
sharesRouter.use(requireAuth, requireVerifiedEmail, csrfGuard);

/** Lazily drops expired pending shares for this user pair-wise. */
async function purgeExpired(userId: string) {
  await prisma.share.deleteMany({
    where: { expiresAt: { lt: new Date() }, OR: [{ senderId: userId }, { recipientId: userId }] },
  });
}

const shareSelect = {
  id: true,
  title: true,
  category: true,
  senderPublicKey: true,
  nonce: true,
  ciphertext: true,
  status: true,
  createdAt: true,
  expiresAt: true,
} as const;

sharesRouter.get('/', async (req, res) => {
  const { user } = getAuth(req);
  await purgeExpired(user.id);

  const [incoming, outgoing] = await Promise.all([
    prisma.share.findMany({
      where: { recipientId: user.id },
      orderBy: { createdAt: 'desc' },
      take: 200,
      select: { ...shareSelect, sender: { select: { email: true, name: true } } },
    }),
    prisma.share.findMany({
      where: { senderId: user.id },
      orderBy: { createdAt: 'desc' },
      take: 200,
      select: { ...shareSelect, recipient: { select: { email: true, name: true } } },
    }),
  ]);

  const map = (
    s: { peer: { email: string; name: string | null } } & Omit<(typeof incoming)[number], 'sender'>,
  ) => ({
    id: s.id,
    title: s.title,
    category: s.category,
    senderPublicKey: s.senderPublicKey,
    nonce: s.nonce,
    ciphertext: s.ciphertext,
    status: s.status,
    createdAt: s.createdAt.toISOString(),
    expiresAt: s.expiresAt ? s.expiresAt.toISOString() : null,
    peer: s.peer,
  });

  res.json({
    incoming: incoming.map(({ sender, ...s }) => map({ ...s, peer: sender })),
    outgoing: outgoing.map(({ recipient, ...s }) => map({ ...s, peer: recipient })),
  });
});

/** Resolves a recipient by email - returns only what the sender needs. */
sharesRouter.get(
  '/lookup',
  dbRateLimit({
    scope: 'share-lookup',
    limit: 30,
    windowMs: 60 * 60 * 1000,
    identifier: userIdentifier,
  }),
  async (req, res) => {
  const { user } = getAuth(req);
  const parsed = emailSchema.safeParse(req.query.email);
  if (!parsed.success) throw new ApiError(400, 'invalid_email', 'Enter a valid email address.');

  const recipient = await prisma.user.findUnique({
    where: { email: parsed.data },
    select: { id: true, email: true, name: true, sharePublicKey: true },
  });
  if (!recipient) {
    throw new ApiError(404, 'not_found', 'No Vaultory account found for that email.');
  }
  if (recipient.id === user.id) {
    throw new ApiError(400, 'self_share', 'You cannot share a secret with yourself.');
  }
  if (!recipient.sharePublicKey) {
    throw new ApiError(
      409,
      'share_key_missing',
      'That user cannot receive shares yet - they need to sign in and open Sharing once.',
    );
  }
  res.json({ email: recipient.email, name: recipient.name, sharePublicKey: recipient.sharePublicKey });
  },
);

sharesRouter.post('/', async (req, res) => {
  const { user } = getAuth(req);
  const body = parseBody(createShareSchema, req);

  const recipient = await prisma.user.findUnique({
    where: { email: body.recipientEmail },
    select: { id: true, sharePublicKey: true },
  });
  if (!recipient) {
    throw new ApiError(404, 'not_found', 'No Vaultory account found for that email.');
  }
  if (recipient.id === user.id) {
    throw new ApiError(400, 'self_share', 'You cannot share a secret with yourself.');
  }
  if (!recipient.sharePublicKey) {
    throw new ApiError(
      409,
      'share_key_missing',
      'That user cannot receive shares yet - they need to sign in and open Sharing once.',
    );
  }

  const pending = await prisma.share.count({ where: { senderId: user.id, status: 'PENDING' } });
  if (pending >= 50) {
    throw new ApiError(429, 'too_many', 'Too many pending shares - revoke some first.');
  }

  const share = await prisma.share.create({
    data: {
      senderId: user.id,
      recipientId: recipient.id,
      title: body.title,
      category: body.category as never,
      senderPublicKey: body.senderPublicKey,
      nonce: body.nonce,
      ciphertext: body.ciphertext,
      expiresAt: body.expiresInDays
        ? new Date(Date.now() + body.expiresInDays * 24 * 60 * 60 * 1000)
        : null,
    },
  });

  await recordActivity({
    userId: user.id,
    type: 'SHARE_SENT',
    targetType: 'secret',
    targetId: share.id,
    targetLabel: body.title,
    req,
  });

  res.status(201).json({ id: share.id });
});

sharesRouter.post('/:id/accept', async (req, res) => {
  const { user } = getAuth(req);
  const share = await prisma.share.findUnique({ where: { id: req.params.id } });
  if (!share || share.recipientId !== user.id || share.status !== 'PENDING') {
    throw new ApiError(404, 'not_found', 'Share not found.');
  }
  if (share.expiresAt && share.expiresAt < new Date()) {
    await prisma.share.delete({ where: { id: share.id } });
    throw new ApiError(410, 'expired', 'This share has expired.');
  }

  await prisma.share.update({ where: { id: share.id }, data: { status: 'ACCEPTED' } });
  await recordActivity({
    userId: user.id,
    type: 'SHARE_ACCEPTED',
    targetType: 'secret',
    targetId: share.id,
    targetLabel: share.title,
    req,
  });
  res.json({ accepted: true });
});

/** Recipient declines → row is removed outright. */
sharesRouter.post('/:id/decline', async (req, res) => {
  const { user } = getAuth(req);
  const share = await prisma.share.findUnique({ where: { id: req.params.id } });
  if (!share || share.recipientId !== user.id) throw new ApiError(404, 'not_found', 'Share not found.');
  await prisma.share.delete({ where: { id: share.id } });
  res.json({ declined: true });
});

/** Sender revokes / recipient dismisses an accepted share. */
sharesRouter.delete('/:id', async (req, res) => {
  const { user } = getAuth(req);
  const share = await prisma.share.findUnique({ where: { id: req.params.id } });
  if (!share || (share.senderId !== user.id && share.recipientId !== user.id)) {
    throw new ApiError(404, 'not_found', 'Share not found.');
  }
  await prisma.share.delete({ where: { id: share.id } });
  if (share.senderId === user.id) {
    await recordActivity({
      userId: user.id,
      type: 'SHARE_REVOKED',
      targetType: 'secret',
      targetId: share.id,
      targetLabel: share.title,
      req,
    });
  }
  res.json({ deleted: true });
});
