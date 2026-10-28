import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../../db/prisma.js';
import { csrfGuard, getAuth, requireAuth, requireVerifiedEmail } from '../../middleware/auth.js';
import { recordActivity } from '../../services/activity.js';
import { ApiError } from '../../utils/http.js';
import { parseBody } from '../../utils/request.js';
import { emailSchema } from '../../utils/validation.js';

/**
 * Emergency access.
 *
 * At grant time the grantor's browser wraps their vault key under
 * ECDH(ephemeral, grantee share key) - the same envelope as secure shares.
 * The server stores that ciphertext and only releases it to the grantee
 * once the wait period has elapsed without the grantor cancelling. The
 * server cannot read the key, but it *is* the policy point for the wait -
 * documented in docs/security.md.
 */

const createGrantSchema = z.object({
  granteeEmail: emailSchema,
  waitDays: z.number().int().min(0).max(30),
  handoverSenderPublicKey: z.string().min(80).max(128),
  handoverNonce: z.string().min(16).max(32),
  handoverCiphertext: z.string().min(1).max(8_192),
});

const grantSelect = {
  id: true,
  status: true,
  waitDays: true,
  requestedAt: true,
  waitUntil: true,
  approvedAt: true,
  createdAt: true,
} as const;

function mapGrant(
  grant: { id: string } & Record<string, unknown> & {
    status: string;
    waitDays: number;
    requestedAt: Date | null;
    waitUntil: Date | null;
    approvedAt: Date | null;
    createdAt: Date;
  },
  peer: { email: string; name: string | null } | undefined,
) {
  return {
    id: grant.id,
    status: grant.status,
    waitDays: grant.waitDays,
    requestedAt: grant.requestedAt ? grant.requestedAt.toISOString() : null,
    waitUntil: grant.waitUntil ? grant.waitUntil.toISOString() : null,
    approvedAt: grant.approvedAt ? grant.approvedAt.toISOString() : null,
    createdAt: grant.createdAt.toISOString(),
    peer: peer ? { email: peer.email, name: peer.name } : null,
  };
}

export const emergencyRouter = Router();
emergencyRouter.use(requireAuth, requireVerifiedEmail, csrfGuard);

emergencyRouter.get('/', async (req, res) => {
  const { user } = getAuth(req);
  const [asGrantor, asGrantee] = await Promise.all([
    prisma.emergencyGrant.findMany({
      where: { grantorId: user.id },
      orderBy: { createdAt: 'desc' },
      take: 100,
      select: { ...grantSelect, grantee: { select: { email: true, name: true } } },
    }),
    prisma.emergencyGrant.findMany({
      where: { granteeId: user.id },
      orderBy: { createdAt: 'desc' },
      take: 100,
      select: {
        ...grantSelect,
        grantor: { select: { email: true, name: true } },
        // Include the handover envelope only once it is actually released.
        handoverSenderPublicKey: true,
        handoverNonce: true,
        handoverCiphertext: true,
      },
    }),
  ]);

  res.json({
    asGrantor: asGrantor.map((g) => mapGrant(g, g.grantee)),
    asGrantee: asGrantee.map((g) => {
      const released = g.status === 'APPROVED';
      return {
        ...mapGrant(g, g.grantor),
        handover: released
          ? {
              senderPublicKey: g.handoverSenderPublicKey,
              nonce: g.handoverNonce,
              ciphertext: g.handoverCiphertext,
            }
          : null,
      };
    }),
  });
});

emergencyRouter.post('/', async (req, res) => {
  const { user } = getAuth(req);
  const body = parseBody(createGrantSchema, req);

  const grantee = await prisma.user.findUnique({
    where: { email: body.granteeEmail },
    select: { id: true, sharePublicKey: true },
  });
  if (!grantee) {
    throw new ApiError(404, 'not_found', 'No Vaultory account found for that email.');
  }
  if (grantee.id === user.id) {
    throw new ApiError(400, 'self_grant', 'You cannot add yourself as a trusted contact.');
  }
  if (!grantee.sharePublicKey) {
    throw new ApiError(
      409,
      'share_key_missing',
      'That user cannot be a trusted contact yet - they need to sign in once.',
    );
  }

  const existing = await prisma.emergencyGrant.findFirst({
    where: { grantorId: user.id, granteeId: grantee.id, status: { not: 'CANCELLED' } },
  });
  if (existing) throw new ApiError(409, 'exists', 'That contact is already configured.');

  const grant = await prisma.emergencyGrant.create({
    data: {
      grantorId: user.id,
      granteeId: grantee.id,
      waitDays: body.waitDays,
      handoverSenderPublicKey: body.handoverSenderPublicKey,
      handoverNonce: body.handoverNonce,
      handoverCiphertext: body.handoverCiphertext,
    },
  });

  await recordActivity({
    userId: user.id,
    type: 'EMERGENCY_GRANTED',
    targetType: 'account',
    targetId: grant.id,
    targetLabel: body.granteeEmail,
    req,
  });

  res.status(201).json({ id: grant.id });
});

/** Grantee starts the wait period. */
emergencyRouter.post('/:id/request', async (req, res) => {
  const { user } = getAuth(req);
  const grant = await prisma.emergencyGrant.findUnique({ where: { id: req.params.id } });
  if (!grant || grant.granteeId !== user.id || grant.status !== 'PENDING') {
    throw new ApiError(404, 'not_found', 'Grant not found.');
  }

  const now = new Date();
  await prisma.emergencyGrant.update({
    where: { id: grant.id },
    data: {
      status: 'WAITING',
      requestedAt: now,
      waitUntil: new Date(now.getTime() + grant.waitDays * 24 * 60 * 60 * 1000),
    },
  });
  await recordActivity({
    userId: user.id,
    type: 'EMERGENCY_REQUESTED',
    targetType: 'account',
    targetId: grant.id,
    req,
  });
  res.json({ requested: true });
});

/** Grantor short-circuits the wait and releases the key immediately. */
emergencyRouter.post('/:id/approve', async (req, res) => {
  const { user } = getAuth(req);
  const grant = await prisma.emergencyGrant.findUnique({ where: { id: req.params.id } });
  if (!grant || grant.grantorId !== user.id || !['PENDING', 'WAITING'].includes(grant.status)) {
    throw new ApiError(404, 'not_found', 'Grant not found.');
  }
  const now = new Date();
  await prisma.emergencyGrant.update({
    where: { id: grant.id },
    data: { status: 'WAITING', requestedAt: grant.requestedAt ?? now, waitUntil: now },
  });
  await recordActivity({
    userId: user.id,
    type: 'EMERGENCY_APPROVED',
    targetType: 'account',
    targetId: grant.id,
    req,
  });
  res.json({ approved: true });
});

/** Grantor cancels the request; either party may also remove a finished grant. */
emergencyRouter.post('/:id/cancel', async (req, res) => {
  const { user } = getAuth(req);
  const grant = await prisma.emergencyGrant.findUnique({ where: { id: req.params.id } });
  if (!grant || (grant.grantorId !== user.id && grant.granteeId !== user.id)) {
    throw new ApiError(404, 'not_found', 'Grant not found.');
  }
  await prisma.emergencyGrant.delete({ where: { id: grant.id } });
  if (grant.grantorId === user.id) {
    await recordActivity({
      userId: user.id,
      type: 'EMERGENCY_CANCELLED',
      targetType: 'account',
      targetId: grant.id,
      req,
    });
  }
  res.json({ cancelled: true });
});

/**
 * Grantee collects the wrapped vault key once the wait has elapsed.
 * Marks the grant APPROVED so repeated access works until cancelled.
 */
emergencyRouter.post('/:id/access', async (req, res) => {
  const { user } = getAuth(req);
  const grant = await prisma.emergencyGrant.findUnique({ where: { id: req.params.id } });
  if (!grant || grant.granteeId !== user.id || grant.status !== 'WAITING') {
    throw new ApiError(404, 'not_found', 'Grant not found.');
  }
  if (!grant.waitUntil || grant.waitUntil > new Date()) {
    throw new ApiError(409, 'waiting', 'The waiting period has not finished yet.');
  }
  if (!grant.handoverCiphertext || !grant.handoverNonce || !grant.handoverSenderPublicKey) {
    throw new ApiError(410, 'no_handover', 'The grantor has not prepared a vault key for this grant.');
  }

  await prisma.emergencyGrant.update({
    where: { id: grant.id },
    data: { status: 'APPROVED', approvedAt: new Date() },
  });
  await recordActivity({
    userId: user.id,
    type: 'EMERGENCY_USED',
    targetType: 'account',
    targetId: grant.id,
    req,
  });
  // Also flag on the grantor's audit feed.
  await recordActivity({
    userId: grant.grantorId,
    type: 'EMERGENCY_USED',
    targetType: 'account',
    targetId: grant.id,
    targetLabel: user.email,
  });

  res.json({
    senderPublicKey: grant.handoverSenderPublicKey,
    nonce: grant.handoverNonce,
    ciphertext: grant.handoverCiphertext,
  });
});

/**
 * Read-only vault export for the grantee: the grantor's live secrets and
 * attachment ciphertext. The grantee holds the vault key locally - the
 * server just relays ciphertext, exactly like a normal secrets listing.
 */
emergencyRouter.get('/:id/vault', async (req, res) => {
  const { user } = getAuth(req);
  const grant = await prisma.emergencyGrant.findUnique({ where: { id: req.params.id } });
  if (!grant || grant.granteeId !== user.id || grant.status !== 'APPROVED') {
    throw new ApiError(404, 'not_found', 'Emergency access is not active for this grant.');
  }

  const [secrets, attachments] = await Promise.all([
    prisma.secret.findMany({
      where: { userId: grant.grantorId, deletedAt: null },
      orderBy: { title: 'asc' },
    }),
    prisma.attachment.findMany({
      where: { secret: { userId: grant.grantorId, deletedAt: null } },
    }),
  ]);

  res.json({
    secrets: secrets.map((s) => ({
      id: s.id,
      title: s.title,
      category: s.category,
      encVersion: s.encVersion,
      keyVersion: s.keyVersion,
      nonce: s.nonce,
      ciphertext: s.ciphertext,
      createdAt: s.createdAt.toISOString(),
      updatedAt: s.updatedAt.toISOString(),
    })),
    attachments: attachments.map((a) => ({
      id: a.id,
      secretId: a.secretId,
      fileName: a.fileName,
      mimeType: a.mimeType,
      size: a.size,
      encVersion: a.encVersion,
      keyVersion: a.keyVersion,
      nonce: a.nonce,
      ciphertext: a.ciphertext,
    })),
  });
});
