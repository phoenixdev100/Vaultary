import { Router } from 'express';
import { z } from 'zod';
import { csrfGuard, getAuth, requireAuth, requireVerifiedEmail } from '../../middleware/auth.js';
import { listActivity, recordActivity } from '../../services/activity.js';
import { prisma } from '../../db/prisma.js';
import { toActivityDto } from '../../utils/dto.js';
import { idSchema } from '../../utils/validation.js';
import { parseBody, parseQuery } from '../../utils/request.js';

const listQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  cursor: idSchema.optional(),
});

/**
 * Client-reportable events. `.env` export happens entirely in the browser, so
 * the audit entry has to be reported by the client - the whitelist keeps this
 * endpoint from becoming a free-form log injector.
 */
const reportSchema = z.object({
  type: z.enum(['SECRETS_EXPORTED']),
  count: z.number().int().min(1).max(10_000),
});

export const activityRouter = Router();

activityRouter.use(requireAuth, requireVerifiedEmail, csrfGuard);

activityRouter.get('/', async (req, res) => {
  const { user } = getAuth(req);
  const { limit, cursor } = parseQuery(listQuerySchema, req);
  const { events, nextCursor } = await listActivity(user.id, { limit, cursor });
  res.json({ items: events.map(toActivityDto), nextCursor });
});

const heatmapQuerySchema = z.object({
  days: z.coerce.number().int().min(7).max(400).default(371),
});

/**
 * Per-day event counts for the dashboard heatmap. Only `createdAt` leaves the
 * database (no labels/IPs); the cap keeps a pathological row count from
 * dragging the response. Aggregation happens here so the client renders a
 * year of history with one small payload.
 */
activityRouter.get('/heatmap', async (req, res) => {
  const { user } = getAuth(req);
  const { days } = parseQuery(heatmapQuerySchema, req);

  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const rows = await prisma.activityEvent.findMany({
    where: { userId: user.id, createdAt: { gte: since } },
    select: { createdAt: true },
    take: 20_000,
  });

  const counts: Record<string, number> = {};
  for (const row of rows) {
    const day = row.createdAt.toISOString().slice(0, 10);
    counts[day] = (counts[day] ?? 0) + 1;
  }

  res.json({ days: counts, truncated: rows.length === 20_000 });
});

activityRouter.post('/', async (req, res) => {
  const { user } = getAuth(req);
  const body = parseBody(reportSchema, req);

  await recordActivity({
    userId: user.id,
    type: body.type,
    targetType: 'secret',
    targetLabel: `${body.count} item${body.count === 1 ? '' : 's'}`,
    req,
  });

  res.status(201).json({ recorded: true });
});
