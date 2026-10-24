import type { Request, RequestHandler } from 'express';
import { env } from '../config/env.js';
import { prisma } from '../db/prisma.js';
import type { Session, User } from '../generated/prisma/client.js';
import { SESSION_COOKIE, clearSessionCookie, deriveCsrfToken } from '../services/session.js';
import { hashToken, timingSafeEqualString } from '../utils/crypto.js';
import { ApiError } from '../utils/http.js';

const LAST_SEEN_THROTTLE_MS = 5 * 60 * 1000;

/**
 * Session token carriers: the httpOnly cookie for browsers, or an
 * `Authorization: Bearer` header for non-cookie clients (the browser
 * extension). Bearer is a secret credential, not ambient auth, so it is
 * also exempt from CSRF - flagged on the request for `csrfGuard`.
 */
function sessionToken(req: Request): { token: string | undefined; bearer: boolean } {
  const header = req.get('authorization');
  if (header?.toLowerCase().startsWith('bearer ')) {
    return { token: header.slice(7).trim() || undefined, bearer: true };
  }
  return { token: (req.cookies as Record<string, string> | undefined)?.[SESSION_COOKIE], bearer: false };
}

/**
 * Resolves the session into a real user row on every request.
 *
 * This is the only source of identity in the API: no handler may accept a
 * user id from the request body, query string or a header.
 */
export const requireAuth: RequestHandler = async (req, res, next) => {
  const { token, bearer } = sessionToken(req);
  if (!token) {
    next(ApiError.unauthorized());
    return;
  }

  const session = await prisma.session.findUnique({
    where: { tokenHash: hashToken(token) },
    include: { user: true },
  });

  if (!session || session.revokedAt !== null || session.expiresAt <= new Date()) {
    clearSessionCookie(res);
    next(ApiError.unauthorized('Your session has expired. Please sign in again.'));
    return;
  }

  const { user, ...sessionRow } = session;
  req.auth = { user, session: sessionRow };
  req.bearerAuth = bearer;

  if (Date.now() - session.lastSeenAt.getTime() > LAST_SEEN_THROTTLE_MS) {
    void prisma.session
      .update({ where: { id: session.id }, data: { lastSeenAt: new Date() } })
      .catch(() => undefined);
  }

  next();
};

/** Typed accessor that fails loudly if a route forgot `requireAuth`. */
export function getAuth(req: Request): { user: User; session: Session } {
  if (!req.auth) throw ApiError.unauthorized();
  return req.auth;
}

export const requireVerifiedEmail: RequestHandler = (req, _res, next) => {
  if (!env.REQUIRE_EMAIL_VERIFICATION) {
    next();
    return;
  }
  const { user } = getAuth(req);
  if (user.emailVerifiedAt === null) {
    next(new ApiError(403, 'email_not_verified', 'Verify your email address to use your vault.'));
    return;
  }
  next();
};

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Synchronizer-token CSRF check, run after `requireAuth` so it can compare
 * against the token bound to this exact session. A double-submit cookie would
 * not work in cross-site deployments (the frontend cannot read the API's
 * cookies), so the token is handed out in JSON and echoed in a header.
 */
export const csrfGuard: RequestHandler = (req, _res, next) => {
  // Bearer-token clients (extension) can't be CSRF'd - the token is a
  // caller-held secret, not an ambient cookie.
  if (!UNSAFE_METHODS.has(req.method) || req.bearerAuth) {
    next();
    return;
  }

  const cookie = (req.cookies as Record<string, string> | undefined)?.[SESSION_COOKIE] ?? '';
  const provided = req.get('x-csrf-token');
  if (!provided || !timingSafeEqualString(provided, deriveCsrfToken(cookie))) {
    next(new ApiError(403, 'csrf_failed', 'Your request could not be verified. Please refresh and try again.'));
    return;
  }

  next();
};
