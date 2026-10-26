import type { Request } from 'express';
import { logger } from '../config/logger.js';
import { prisma } from '../db/prisma.js';
import type { ActivityType } from '../generated/prisma/client.js';
import { getIpLabel, getUserAgent } from '../utils/request.js';

interface RecordActivityParams {
  userId: string;
  type: ActivityType;
  targetType?: 'secret' | 'folder' | 'account' | 'session' | 'attachment';
  targetId?: string;
  /** Non-sensitive label (secret title / folder name). Never a secret value. */
  targetLabel?: string | null;
  req?: Request;
}

/**
 * Appends an audit entry. Only metadata is stored: the activity log never
 * contains secret values, and a logging failure must not fail the user's
 * actual operation.
 */
export async function recordActivity(params: RecordActivityParams): Promise<void> {
  try {
    await prisma.activityEvent.create({
      data: {
        userId: params.userId,
        type: params.type,
        targetType: params.targetType ?? null,
        targetId: params.targetId ?? null,
        targetLabel: params.targetLabel ? params.targetLabel.slice(0, 200) : null,
        ipLabel: params.req ? getIpLabel(params.req) : null,
        userAgent: params.req ? getUserAgent(params.req) : null,
      },
    });
  } catch (error) {
    logger.warn({ err: error, type: params.type }, 'Failed to record activity event');
  }
}

export async function listActivity(userId: string, options: { limit: number; cursor?: string | undefined }) {
  const events = await prisma.activityEvent.findMany({
    where: { userId },
    // id as tiebreaker: createdAt is not unique, so rows sharing a timestamp
    // at a page boundary would otherwise be skipped or duplicated.
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    take: options.limit + 1,
    ...(options.cursor ? { cursor: { id: options.cursor }, skip: 1 } : {}),
  });

  const hasMore = events.length > options.limit;
  return { events: hasMore ? events.slice(0, options.limit) : events, nextCursor: hasMore ? events[options.limit - 1]?.id ?? null : null };
}
