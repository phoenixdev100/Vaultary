import type { RequestHandler } from 'express';
import { env } from '../config/env.js';
import { ApiError } from '../utils/http.js';

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

const EXTENSION_SCHEME = /^(chrome-extension|moz-extension|edge-extension|safari-web-extension):\/\//;

export function isAllowedOrigin(origin: string): boolean {
  // A browser extension is installed client software holding the caller's own
  // credentials - the same trust class as curl, not ambient web state. The
  // scheme check also covers CORS, whose preflight echoes this function.
  if (EXTENSION_SCHEME.test(origin)) return true;
  return env.CORS_ORIGINS.includes(origin.replace(/\/$/, ''));
}

/**
 * First line of CSRF defence for *unauthenticated* state-changing routes
 * (login, signup, password reset) where no session token exists yet.
 *
 * Browsers always attach `Origin` to cross-site POST requests, so an
 * unexpected origin is rejected outright. Requests without an `Origin` header
 * (curl, server-to-server, tests) are allowed through - session routes are
 * still protected by `csrfGuard`.
 */
export const originGuard: RequestHandler = (req, _res, next) => {
  if (!UNSAFE_METHODS.has(req.method)) {
    next();
    return;
  }

  // Bearer credentials are caller-held secrets, not ambient browser state: a
  // cross-site page cannot attach them, so a `chrome-extension://` (or any)
  // origin carrying one is not a CSRF vector. When a Bearer header is present
  // `requireAuth` ignores the cookie entirely, so ambient auth can't be
  // smuggled past this guard either.
  const bearer = req.get('authorization')?.toLowerCase().startsWith('bearer ') ?? false;

  const origin = req.get('origin');
  if (origin && !isAllowedOrigin(origin) && !bearer) {
    next(new ApiError(403, 'origin_not_allowed', 'Requests from this origin are not allowed.'));
    return;
  }

  next();
};
