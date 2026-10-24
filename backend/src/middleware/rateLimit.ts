import type { Request, RequestHandler } from 'express';
import { rateLimit } from 'express-rate-limit';
import { isTest } from '../config/env.js';
import { logger } from '../config/logger.js';
import { prisma } from '../db/prisma.js';
import { rateLimitKey } from '../utils/crypto.js';
import { ApiError } from '../utils/http.js';
import { getIpLabel } from '../utils/request.js';

interface DbRateLimitOptions {
  scope: string;
  limit: number;
  windowMs: number;
  /** Bucket identity, e.g. ip, or `${email}|${ip}`. Hashed before storage. */
  identifier: (req: Request) => string;
  message?: string;
}

/**
 * Increments a database bucket and throws 429 past the limit. Extracted so
 * routes can also count selectively (e.g. only favicon cache misses), not
 * just as whole-route middleware.
 */
export async function consumeRateLimit(
  options: Omit<DbRateLimitOptions, 'identifier'>,
  identifier: string,
): Promise<void> {
  const key = rateLimitKey(options.scope, identifier);
  const now = new Date();
  const windowEnd = new Date(now.getTime() + options.windowMs);

  try {
    const counter = await prisma.$transaction(async (tx) => {
      const existing = await tx.rateLimitCounter.findUnique({ where: { key } });

      if (!existing || existing.windowEnd <= now) {
        return tx.rateLimitCounter.upsert({
          where: { key },
          create: { key, count: 1, windowEnd },
          update: { count: 1, windowEnd },
        });
      }

      return tx.rateLimitCounter.update({ where: { key }, data: { count: { increment: 1 } } });
    });

    if (counter.count > options.limit) {
      const retryAfter = Math.ceil((counter.windowEnd.getTime() - now.getTime()) / 1000);
      throw ApiError.tooManyRequests(
        options.message ?? 'Too many attempts. Please wait a moment and try again.',
        retryAfter,
      );
    }

    // Opportunistic cleanup: expired rate-limit buckets plus lapsed sessions
    // and tokens, so stale rows never accumulate without a cron job.
    if (Math.random() < 0.02) {
      const past = new Date(now.getTime() - 60 * 60 * 1000);
      void Promise.all([
        prisma.rateLimitCounter.deleteMany({ where: { windowEnd: { lt: past } } }),
        prisma.session.deleteMany({ where: { expiresAt: { lt: past } } }),
        prisma.verificationToken.deleteMany({ where: { expiresAt: { lt: past } } }),
      ]).catch(() => undefined);
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    logger.warn({ scope: options.scope }, 'Rate limit store unavailable, allowing request');
  }
}

/**
 * Database-backed limiter.
 *
 * Serverless instances do not share memory, so anything that protects
 * credentials (login, signup, password reset) is counted in Postgres instead of
 * per-process. Failures are logged and allowed through: the limiter must not
 * become a single point of failure for the whole API.
 */
export function dbRateLimit(options: DbRateLimitOptions): RequestHandler {
  return async (req, _res, next) => {
    try {
      await consumeRateLimit(options, options.identifier(req));
      next();
    } catch (error) {
      next(error);
    }
  };
}

export const ipIdentifier = (req: Request): string => getIpLabel(req) ?? 'unknown';

/** Per-user bucket for authenticated routes (run after `requireAuth`). */
export const userIdentifier = (req: Request): string => req.auth?.user.id ?? ipIdentifier(req);

export const emailAndIpIdentifier = (req: Request): string => {
  const body = req.body as { email?: unknown } | undefined;
  const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase().slice(0, 254) : 'anonymous';
  return `${email}|${ipIdentifier(req)}`;
};

/**
 * Coarse per-instance limiter for everything else. On Vercel this is per warm
 * lambda rather than global - documented in docs/security.md - and exists to
 * blunt accidental request storms, not as the primary credential protection.
 */
export const generalLimiter = rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: { code: 'rate_limited', message: 'Too many requests. Please slow down.' } },
});

/**
 * Auth-path burst limiter, applied to /api/auth/* before the scoped DB
 * counters. Credential stuffing floods die here - in memory - without ever
 * reaching the database. Per warm lambda on serverless, same caveat as the
 * general limiter; the DB counters are still the real enforcement.
 */
export const authBurstLimiter = rateLimit({
  windowMs: 60_000,
  limit: 60,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  // The integration suite drives hundreds of auth calls from one address.
  skip: () => isTest,
  message: {
    error: {
      code: 'rate_limited',
      message: 'Too many attempts in a short time. Please wait a moment and try again.',
    },
  },
});
