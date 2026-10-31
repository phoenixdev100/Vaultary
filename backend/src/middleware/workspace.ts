import type { Request, RequestHandler } from 'express';
import { prisma } from '../db/prisma.js';
import { ApiError } from '../utils/http.js';
import { getAuth } from './auth.js';

export const WORKSPACE_HEADER = 'x-workspace-id';

/** The workspace a request operates inside. Only valid after `workspaceScope`. */
export function getWorkspaceId(req: Request): string {
  if (!req.workspaceId) throw ApiError.unauthorized();
  return req.workspaceId;
}

/**
 * Resolves the X-Workspace-Id header into a workspace owned by the session
 * user and stamps `req.workspaceId`. A missing header falls back to the
 * account's default workspace so older clients (extension builds that do not
 * know about workspaces) keep operating inside Personal.
 *
 * An explicitly supplied id that the user does not own is a 404 - same rule as
 * secrets: foreign workspace existence is never leaked through error codes.
 */
export const workspaceScope: RequestHandler = async (req, _res, next) => {
  const { user } = getAuth(req);
  const requested = req.get(WORKSPACE_HEADER)?.trim();

  if (requested) {
    const workspace = await prisma.workspace.findFirst({
      where: { id: requested, userId: user.id },
      select: { id: true },
    });
    if (!workspace) {
      next(ApiError.notFound('That workspace does not exist.'));
      return;
    }
    req.workspaceId = workspace.id;
    next();
    return;
  }

  const fallback = await prisma.workspace.findFirst({
    where: { userId: user.id },
    orderBy: [{ isDefault: 'desc' }, { createdAt: 'asc' }],
    select: { id: true },
  });
  if (!fallback) {
    // Should be unreachable: signup and the backfill migration guarantee a
    // default workspace. Failing closed keeps vault data unreachable rather
    // than silently mixing scopes.
    next(ApiError.forbidden('Your account has no workspace. Please contact support.'));
    return;
  }
  req.workspaceId = fallback.id;
  next();
};
