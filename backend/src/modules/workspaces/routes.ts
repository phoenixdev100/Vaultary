import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '../../db/prisma.js';
import { csrfGuard, getAuth, requireAuth, requireVerifiedEmail } from '../../middleware/auth.js';
import { recordActivity } from '../../services/activity.js';
import { toWorkspaceDto } from '../../utils/dto.js';
import { ApiError } from '../../utils/http.js';
import { parseBody, parseIdParam, parseQuery } from '../../utils/request.js';

const workspaceNameSchema = z.string().trim().min(1, 'Organisation name is required').max(60);
const workspaceColorSchema = z
  .string()
  .regex(/^#[0-9a-fA-F]{6}$/, 'Colour must be a hex value like #4F46E5')
  .nullish();

const createWorkspaceSchema = z.object({
  name: workspaceNameSchema,
  color: workspaceColorSchema,
});
const updateWorkspaceSchema = z
  .object({ name: workspaceNameSchema.optional(), color: workspaceColorSchema })
  .refine((value) => value.name !== undefined || value.color !== undefined, {
    error: 'Nothing to update.',
  });

/** Deleting a workspace is destructive; an explicit strategy is required. */
const deleteWorkspaceQuerySchema = z.object({
  strategy: z.enum(['require-empty', 'delete-contents']).default('require-empty'),
});

const MAX_WORKSPACES_PER_USER = 25;

async function findOwnedWorkspace(id: string, userId: string) {
  const workspace = await prisma.workspace.findFirst({ where: { id, userId } });
  if (!workspace) throw ApiError.notFound('That organisation does not exist.');
  return workspace;
}

export const workspacesRouter = Router();

workspacesRouter.use(requireAuth, requireVerifiedEmail, csrfGuard);

workspacesRouter.get('/', async (req, res) => {
  const { user } = getAuth(req);
  const items = await prisma.workspace.findMany({
    where: { userId: user.id },
    orderBy: [{ isDefault: 'desc' }, { createdAt: 'asc' }],
    include: { _count: { select: { secrets: { where: { deletedAt: null } }, folders: true } } },
  });

  res.json({
    items: items.map((workspace) => ({
      ...toWorkspaceDto(workspace),
      secretCount: workspace._count.secrets,
      folderCount: workspace._count.folders,
    })),
  });
});

workspacesRouter.post('/', async (req, res) => {
  const { user } = getAuth(req);
  const body = parseBody(createWorkspaceSchema, req);

  const count = await prisma.workspace.count({ where: { userId: user.id } });
  if (count >= MAX_WORKSPACES_PER_USER) {
    throw ApiError.badRequest(`You can create up to ${MAX_WORKSPACES_PER_USER} organisations.`);
  }

  const duplicate = await prisma.workspace.findFirst({
    where: { userId: user.id, name: body.name },
    select: { id: true },
  });
  if (duplicate) throw ApiError.conflict('An organisation with that name already exists.');

  const workspace = await prisma.workspace.create({
    data: { userId: user.id, name: body.name, color: body.color ?? null },
  });

  await recordActivity({
    userId: user.id,
    type: 'WORKSPACE_CREATED',
    targetType: 'workspace',
    targetId: workspace.id,
    targetLabel: workspace.name,
    req,
  });

  res.status(201).json({ workspace: toWorkspaceDto(workspace) });
});

workspacesRouter.patch('/:id', async (req, res) => {
  const { user } = getAuth(req);
  const id = parseIdParam(req);
  const body = parseBody(updateWorkspaceSchema, req);
  const existing = await findOwnedWorkspace(id, user.id);

  if (body.name && body.name !== existing.name) {
    const duplicate = await prisma.workspace.findFirst({
      where: { userId: user.id, name: body.name, id: { not: id } },
      select: { id: true },
    });
    if (duplicate) throw ApiError.conflict('An organisation with that name already exists.');
  }

  const workspace = await prisma.workspace.update({
    where: { id: existing.id },
    data: {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.color !== undefined ? { color: body.color } : {}),
    },
  });

  if (body.name !== undefined && body.name !== existing.name) {
    await recordActivity({
      userId: user.id,
      type: 'WORKSPACE_RENAMED',
      targetType: 'workspace',
      targetId: workspace.id,
      targetLabel: workspace.name,
      req,
    });
  }

  res.json({ workspace: toWorkspaceDto(workspace) });
});

/**
 * Default strategy refuses to delete a non-empty workspace - secrets and
 * folders are never destroyed silently. `delete-contents` hard-deletes the
 * whole workspace (cascade) for users who explicitly want it gone.
 */
workspacesRouter.delete('/:id', async (req, res) => {
  const { user } = getAuth(req);
  const id = parseIdParam(req);
  const { strategy } = parseQuery(deleteWorkspaceQuerySchema, req);

  const workspace = await prisma.workspace.findFirst({
    where: { id, userId: user.id },
    include: { _count: { select: { secrets: true, folders: true } } },
  });
  if (!workspace) throw ApiError.notFound('That organisation does not exist.');

  if (workspace.isDefault) {
    throw ApiError.badRequest('Your default organisation cannot be deleted.');
  }

  const remaining = await prisma.workspace.count({ where: { userId: user.id } });
  if (remaining <= 1) {
    throw ApiError.badRequest('Your account needs at least one organisation.');
  }

  const contents = workspace._count.secrets + workspace._count.folders;
  if (contents > 0 && strategy !== 'delete-contents') {
    throw ApiError.conflict(
      'This organisation still has items in it. Move or delete them first, or delete with the contents.',
    );
  }

  await prisma.workspace.delete({ where: { id: workspace.id } });
  await recordActivity({
    userId: user.id,
    type: 'WORKSPACE_DELETED',
    targetType: 'workspace',
    targetId: workspace.id,
    targetLabel: workspace.name,
    req,
  });

  res.json({ deleted: true, removedItems: contents });
});
