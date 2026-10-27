import { Router } from 'express';
import { prisma } from '../../db/prisma.js';
import { getAuth, requireAuth, requireVerifiedEmail } from '../../middleware/auth.js';
import { toActivityDto, toSecretDto } from '../../utils/dto.js';

export const dashboardRouter = Router();

dashboardRouter.use(requireAuth, requireVerifiedEmail);

dashboardRouter.get('/', async (req, res) => {
  const { user } = getAuth(req);

  const [secretCount, favoriteCount, folderCount, attachmentCount, trashCount, byCategory, recentSecrets, recentActivity, strandedSecrets, passkeyCount, lastExport] =
    await Promise.all([
      prisma.secret.count({ where: { userId: user.id, deletedAt: null } }),
      prisma.secret.count({ where: { userId: user.id, isFavorite: true, deletedAt: null } }),
      prisma.folder.count({ where: { userId: user.id } }),
      prisma.attachment.count({ where: { userId: user.id, secret: { deletedAt: null } } }),
      prisma.secret.count({ where: { userId: user.id, deletedAt: { not: null } } }),
      prisma.secret.groupBy({ by: ['category'], where: { userId: user.id, deletedAt: null }, _count: { _all: true } }),
      prisma.secret.findMany({ where: { userId: user.id, deletedAt: null }, orderBy: { updatedAt: 'desc' }, take: 5 }),
      prisma.activityEvent.findMany({ where: { userId: user.id }, orderBy: { createdAt: 'desc' }, take: 6 }),
      prisma.secret.count({ where: { userId: user.id, deletedAt: null, keyVersion: { lt: user.vaultKeyVersion } } }),
      prisma.passkey.count({ where: { userId: user.id } }),
      prisma.activityEvent.findFirst({
        where: { userId: user.id, type: 'SECRETS_EXPORTED' },
        orderBy: { createdAt: 'desc' },
        select: { createdAt: true },
      }),
    ]);

  res.json({
    counts: {
      secrets: secretCount,
      favorites: favoriteCount,
      folders: folderCount,
      attachments: attachmentCount,
      trash: trashCount,
      strandedSecrets,
    },
    categories: byCategory
      .map((row) => ({ category: row.category, count: row._count._all }))
      .sort((a, b) => b.count - a.count),
    recentSecrets: recentSecrets.map(toSecretDto),
    recentActivity: recentActivity.map(toActivityDto),
    /** Checklist inputs the client cannot see elsewhere: passkey count lives
     * behind /account/passkeys, export recency lives in the activity log. */
    security: {
      passkeyCount,
      lastExportAt: lastExport ? lastExport.createdAt.toISOString() : null,
    },
  });
});
