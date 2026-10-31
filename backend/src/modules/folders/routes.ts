import { Router } from 'express';
import { z } from 'zod';
import { MAX_FOLDER_DEPTH, MAX_FOLDERS_PER_USER } from '../../config/constants.js';
import { prisma } from '../../db/prisma.js';
import { csrfGuard, getAuth, requireAuth, requireVerifiedEmail } from '../../middleware/auth.js';
import { getWorkspaceId, workspaceScope } from '../../middleware/workspace.js';
import { recordActivity } from '../../services/activity.js';
import { toFolderDto } from '../../utils/dto.js';
import { ApiError } from '../../utils/http.js';
import { parseBody, parseIdParam, parseQuery } from '../../utils/request.js';

const folderNameSchema = z.string().trim().min(1, 'Folder name is required').max(60);
const folderColorSchema = z
  .string()
  .regex(/^#[0-9a-fA-F]{6}$/, 'Colour must be a hex value like #4F46E5')
  .nullish();
const parentIdSchema = z.string().uuid().nullish();

const createFolderSchema = z.object({
  name: folderNameSchema,
  color: folderColorSchema,
  parentId: parentIdSchema,
});
const updateFolderSchema = z
  .object({ name: folderNameSchema.optional(), color: folderColorSchema, parentId: parentIdSchema })
  .refine((value) => value.name !== undefined || value.color !== undefined || value.parentId !== undefined, {
    error: 'Nothing to update.',
  });

/** Deleting a folder never silently destroys secrets: the caller must choose. */
const deleteFolderQuerySchema = z.object({
  strategy: z.enum(['detach', 'delete-secrets']).default('detach'),
});

const folderCountInclude = {
  _count: { select: { secrets: { where: { deletedAt: null } }, children: true } },
} as const;

/**
 * Resolves a target parent folder for create/move: it must belong to the user.
 * Throws notFound for foreign or missing ids so folder existence is not leaked.
 */
async function requireOwnedFolder(userId: string, workspaceId: string, parentId: string): Promise<void> {
  const parent = await prisma.folder.findFirst({
    where: { id: parentId, userId, workspaceId },
    select: { id: true },
  });
  if (!parent) throw ApiError.notFound('That parent folder does not exist in this workspace.');
}

/**
 * Depth of a folder's ancestor chain (root parent -> 1). Also detects cycles:
 * a move that would point a folder at itself or one of its own descendants
 * loops forever, so walking up with a visited-set rejects it.
 */
async function ancestorDepth(userId: string, workspaceId: string, startParentId: string | null, forbiddenId?: string) {
  const visited = new Set<string>();
  let current = startParentId;
  let depth = 0;
  while (current) {
    if (current === forbiddenId || visited.has(current)) return -1;
    visited.add(current);
    depth += 1;
    const row = await prisma.folder.findFirst({
      where: { id: current, userId, workspaceId },
      select: { parentId: true },
    });
    if (!row) return -1;
    current = row.parentId;
  }
  return depth;
}

/**
 * Deepest descendant chain below a folder - moving a folder under a new parent
 * must respect MAX_FOLDER_DEPTH for the whole moved subtree, not just the node.
 */
async function deepestChildDepth(userId: string, workspaceId: string, folderId: string): Promise<number> {
  let frontier = [folderId];
  let depth = 0;
  while (frontier.length > 0) {
    const children = await prisma.folder.findMany({
      where: { userId, workspaceId, parentId: { in: frontier } },
      select: { id: true },
    });
    if (children.length === 0) return depth;
    depth += 1;
    frontier = children.map((child) => child.id);
  }
  return depth;
}

export const foldersRouter = Router();

foldersRouter.use(requireAuth, requireVerifiedEmail, csrfGuard, workspaceScope);

foldersRouter.get('/', async (req, res) => {
  const { user } = getAuth(req);
  const workspaceId = getWorkspaceId(req);
  const folders = await prisma.folder.findMany({
    where: { userId: user.id, workspaceId },
    orderBy: { name: 'asc' },
    include: folderCountInclude,
  });

  const unfiled = await prisma.secret.count({
    where: { userId: user.id, workspaceId, folderId: null, deletedAt: null },
  });
  res.json({ items: folders.map(toFolderDto), unfiledCount: unfiled });
});

foldersRouter.post('/', async (req, res) => {
  const { user } = getAuth(req);
  const workspaceId = getWorkspaceId(req);
  const body = parseBody(createFolderSchema, req);

  const count = await prisma.folder.count({ where: { userId: user.id } });
  if (count >= MAX_FOLDERS_PER_USER) {
    throw ApiError.badRequest(`You can create up to ${MAX_FOLDERS_PER_USER} folders.`);
  }

  if (body.parentId) {
    await requireOwnedFolder(user.id, workspaceId, body.parentId);
    const depth = await ancestorDepth(user.id, workspaceId, body.parentId);
    if (depth < 0 || depth + 1 > MAX_FOLDER_DEPTH) {
      throw ApiError.badRequest(`Folders can only be nested ${MAX_FOLDER_DEPTH} levels deep.`);
    }
  }

  const duplicate = await prisma.folder.findFirst({
    where: { userId: user.id, workspaceId, name: body.name },
    select: { id: true },
  });
  if (duplicate) throw ApiError.conflict('A folder with that name already exists.');

  const folder = await prisma.folder.create({
    data: {
      userId: user.id,
      workspaceId,
      name: body.name,
      color: body.color ?? null,
      parentId: body.parentId ?? null,
    },
    include: folderCountInclude,
  });

  await recordActivity({
    userId: user.id,
    type: 'FOLDER_CREATED',
    targetType: 'folder',
    targetId: folder.id,
    targetLabel: folder.name,
    req,
  });

  res.status(201).json({ folder: toFolderDto(folder) });
});

foldersRouter.patch('/:id', async (req, res) => {
  const { user } = getAuth(req);
  const workspaceId = getWorkspaceId(req);
  const id = parseIdParam(req);
  const body = parseBody(updateFolderSchema, req);

  const existing = await prisma.folder.findFirst({ where: { id, userId: user.id, workspaceId } });
  if (!existing) throw ApiError.notFound('That folder does not exist in this workspace.');

  if (body.name && body.name !== existing.name) {
    const duplicate = await prisma.folder.findFirst({
      where: { userId: user.id, workspaceId, name: body.name, id: { not: id } },
      select: { id: true },
    });
    if (duplicate) throw ApiError.conflict('A folder with that name already exists.');
  }

  // Moving a folder: the new parent must be owned, must not be the folder
  // itself or one of its descendants, and the moved subtree must fit the
  // depth limit at its new level.
  if (body.parentId !== undefined && body.parentId !== existing.parentId) {
    if (body.parentId !== null) {
      await requireOwnedFolder(user.id, workspaceId, body.parentId);
      const parentDepth = await ancestorDepth(user.id, workspaceId, body.parentId, id);
      if (parentDepth < 0) {
        throw ApiError.badRequest('A folder cannot be moved inside itself or its own subfolder.');
      }
      const childDepth = await deepestChildDepth(user.id, workspaceId, existing.id);
      if (parentDepth + 1 + childDepth > MAX_FOLDER_DEPTH) {
        throw ApiError.badRequest(`That move would exceed the ${MAX_FOLDER_DEPTH}-level nesting limit.`);
      }
    }
    // parentId === null means "move to the top level" - always allowed.
  }

  const folder = await prisma.folder.update({
    where: { id: existing.id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.color !== undefined ? { color: body.color } : {}),
      ...(body.parentId !== undefined ? { parentId: body.parentId ?? null } : {}),
    },
    include: folderCountInclude,
  });

  await recordActivity({
    userId: user.id,
    type: 'FOLDER_RENAMED',
    targetType: 'folder',
    targetId: folder.id,
    targetLabel: folder.name,
    req,
  });

  res.json({ folder: toFolderDto(folder) });
});

foldersRouter.delete('/:id', async (req, res) => {
  const { user } = getAuth(req);
  const workspaceId = getWorkspaceId(req);
  const id = parseIdParam(req);
  const { strategy } = parseQuery(deleteFolderQuerySchema, req);

  const folder = await prisma.folder.findFirst({
    where: { id, userId: user.id, workspaceId },
    include: { _count: { select: { secrets: true, children: true } } },
  });
  if (!folder) throw ApiError.notFound('That folder does not exist in this workspace.');

  const deleteSecrets = strategy === 'delete-secrets';
  // Children are lifted to this folder's parent so the tree shape survives -
  // only the removed level disappears. Secrets fall back to "Unfiled"
  // (schema uses onDelete: SetNull on both relations as the safety net).
  // Secrets inside child folders keep their folder because children are
  // reparented, not deleted. All writes share one transaction so a failure
  // cannot strand secrets already deleted against a folder that survives.
  const detachedFolders = folder._count.children;
  const deletedSecrets = await prisma.$transaction(async (tx) => {
    let count = 0;
    if (deleteSecrets) {
      count = (
        await tx.secret.deleteMany({ where: { userId: user.id, workspaceId, folderId: folder.id } })
      ).count;
    }
    await tx.folder.updateMany({
      where: { userId: user.id, workspaceId, parentId: folder.id },
      data: { parentId: folder.parentId },
    });
    await tx.folder.delete({ where: { id: folder.id } });
    return count;
  });

  await recordActivity({
    userId: user.id,
    type: 'FOLDER_DELETED',
    targetType: 'folder',
    targetId: folder.id,
    targetLabel: folder.name,
    req,
  });

  res.json({
    deleted: true,
    deletedSecrets,
    detachedSecrets: strategy === 'detach' ? folder._count.secrets : 0,
    detachedFolders,
  });
});
