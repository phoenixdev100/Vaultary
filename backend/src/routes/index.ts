import { Router } from 'express';
import { prisma } from '../db/prisma.js';
import { authBurstLimiter } from '../middleware/rateLimit.js';
import { activityRouter } from '../modules/activity/routes.js';
import { authRouter } from '../modules/auth/routes.js';
import { dashboardRouter } from '../modules/dashboard/routes.js';
import { emergencyRouter } from '../modules/emergency/routes.js';
import { foldersRouter } from '../modules/folders/routes.js';
import { metaRouter } from '../modules/meta/routes.js';
import { favoritesRouter, secretsRouter } from '../modules/secrets/routes.js';
import { accountRouter, settingsRouter } from '../modules/settings/routes.js';
import { sharesRouter } from '../modules/shares/routes.js';

export const apiRouter = Router();

apiRouter.get('/health', async (_req, res) => {
  let database = 'down';
  try {
    await prisma.$queryRaw`SELECT 1`;
    database = 'up';
  } catch {
    // Detail is intentionally not returned to the caller.
  }

  res.status(database === 'up' ? 200 : 503).json({
    status: database === 'up' ? 'ok' : 'degraded',
    service: 'vaultory-api',
    database,
    timestamp: new Date().toISOString(),
  });
});

apiRouter.use('/auth', authBurstLimiter, authRouter);
apiRouter.use('/secrets', secretsRouter);
apiRouter.use('/favorites', favoritesRouter);
apiRouter.use('/folders', foldersRouter);
apiRouter.use('/activity', activityRouter);
apiRouter.use('/settings', settingsRouter);
apiRouter.use('/account', accountRouter);
apiRouter.use('/dashboard', dashboardRouter);
apiRouter.use('/meta', metaRouter);
apiRouter.use('/shares', sharesRouter);
apiRouter.use('/emergency', emergencyRouter);
