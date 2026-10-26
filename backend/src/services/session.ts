import type { CookieOptions, Request, Response } from 'express';
import { env, isProduction } from '../config/env.js';
import { prisma } from '../db/prisma.js';
import type { Session } from '../generated/prisma/client.js';
import { generateToken, hashToken } from '../utils/crypto.js';
import { getCountryCode, getIpLabel, getUserAgent } from '../utils/request.js';

export const SESSION_COOKIE = 'vaultory_session';

const sessionTtlMs = () => env.SESSION_TTL_DAYS * 24 * 60 * 60 * 1000;

function cookieOptions(maxAgeMs?: number): CookieOptions {
  return {
    httpOnly: true,
    // SameSite=None requires Secure; cross-site mode is opt-in via env.
    secure: isProduction || env.CROSS_SITE_COOKIES,
    sameSite: env.CROSS_SITE_COOKIES ? 'none' : 'lax',
    path: '/',
    ...(env.COOKIE_DOMAIN ? { domain: env.COOKIE_DOMAIN } : {}),
    ...(maxAgeMs !== undefined ? { maxAge: maxAgeMs } : {}),
  };
}

export interface IssuedSession {
  session: Session;
  /** Raw token - only ever written to the Set-Cookie header. */
  token: string;
  /** CSRF token for this session - returned in JSON, kept in memory by the client. */
  csrfToken: string;
}

/**
 * OWASP "HMAC based token" CSRF pattern: the token is a keyed hash of the
 * session token, so it is stable for the life of the session (multi-tab safe),
 * unguessable without SESSION_SECRET, and needs no extra storage.
 */
export function deriveCsrfToken(rawSessionToken: string): string {
  return hashToken(`csrf|${rawSessionToken}`);
}

export async function createSession(userId: string, req: Request): Promise<IssuedSession> {
  const token = generateToken(32);

  const session = await prisma.session.create({
    data: {
      userId,
      tokenHash: hashToken(token),
      userAgent: getUserAgent(req),
      ipLabel: getIpLabel(req),
      country: getCountryCode(req),
      expiresAt: new Date(Date.now() + sessionTtlMs()),
    },
  });

  return { session, token, csrfToken: deriveCsrfToken(token) };
}

export function setSessionCookie(res: Response, issued: IssuedSession): void {
  res.cookie(SESSION_COOKIE, issued.token, cookieOptions(issued.session.expiresAt.getTime() - Date.now()));
}

export function clearSessionCookie(res: Response): void {
  res.clearCookie(SESSION_COOKIE, cookieOptions());
}

export async function revokeSession(sessionId: string, userId: string): Promise<boolean> {
  const result = await prisma.session.updateMany({
    where: { id: sessionId, userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  return result.count > 0;
}

export async function revokeOtherSessions(userId: string, keepSessionId: string): Promise<number> {
  const result = await prisma.session.updateMany({
    where: { userId, id: { not: keepSessionId }, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  return result.count;
}

export function listSessions(userId: string) {
  return prisma.session.findMany({
    where: { userId, revokedAt: null, expiresAt: { gt: new Date() } },
    orderBy: { lastSeenAt: 'desc' },
    take: 50,
  });
}
