import { Router } from 'express';
import {
  MAX_ATTACHMENTS_PER_SECRET,
  MAX_VERSIONS_PER_SECRET,
  TRASH_RETENTION_DAYS,
} from '../../config/constants.js';
import { prisma } from '../../db/prisma.js';
import type { Prisma, Secret } from '../../generated/prisma/client.js';
import { csrfGuard, getAuth, requireAuth, requireVerifiedEmail } from '../../middleware/auth.js';
import { getWorkspaceId, workspaceScope } from '../../middleware/workspace.js';
import { recordActivity } from '../../services/activity.js';
import { toAttachmentDto, toSecretDto, toSecretVersionDto } from '../../utils/dto.js';
import { ApiError } from '../../utils/http.js';
import { parseBody, parseIdParam, parseQuery } from '../../utils/request.js';
import {
  bulkCreateSecretsSchema,
  createAttachmentSchema,
  createSecretSchema,
  listSecretsQuerySchema,
  updateSecretSchema,
} from './schemas.js';

export const secretsRouter = Router();

secretsRouter.use(requireAuth, requireVerifiedEmail, csrfGuard, workspaceScope);

/** Ownership is always re-checked against the session user, never the payload. */
async function findOwnedSecret(id: string, userId: string, workspaceId: string): Promise<Secret> {
  const secret = await prisma.secret.findFirst({ where: { id, userId, workspaceId, deletedAt: null } });
  if (!secret) throw ApiError.notFound('That item is not in your vault.');
  return secret;
}

/** Only matches rows that are actually in the trash. */
async function findTrashedSecret(id: string, userId: string, workspaceId: string): Promise<Secret> {
  const secret = await prisma.secret.findFirst({
    where: { id, userId, workspaceId, deletedAt: { not: null } },
  });
  if (!secret) throw ApiError.notFound('That item is not in the trash.');
  return secret;
}

/** Permanently deletes rows past the retention window. Runs lazily on reads. */
async function purgeExpiredTrash(userId: string, workspaceId: string): Promise<void> {
  const cutoff = new Date(Date.now() - TRASH_RETENTION_DAYS * 24 * 60 * 60 * 1000);
  await prisma.secret.deleteMany({ where: { userId, workspaceId, deletedAt: { lt: cutoff } } });
}

async function assertFolderOwned(
  folderId: string | null | undefined,
  userId: string,
  workspaceId: string,
): Promise<void> {
  if (!folderId) return;
  const folder = await prisma.folder.findFirst({
    where: { id: folderId, userId, workspaceId },
    select: { id: true },
  });
  if (!folder) throw ApiError.badRequest('That folder does not exist in this workspace.');
}

function buildWhere(
  userId: string,
  workspaceId: string,
  filters: ReturnType<typeof listSecretsQuerySchema.parse>,
) {
  const where: Prisma.SecretWhereInput = { userId, workspaceId, deletedAt: null };

  if (filters.category) where.category = filters.category;
  if (filters.favorite !== undefined) where.isFavorite = filters.favorite;
  if (filters.tag) where.tags = { has: filters.tag };
  if (filters.folderId) where.folderId = filters.folderId === 'none' ? null : filters.folderId;
  if (filters.query) {
    // Only non-sensitive metadata is searchable server-side; secret values are
    // ciphertext here and are searched in the browser after decryption.
    where.OR = [
      { title: { contains: filters.query, mode: 'insensitive' } },
      { tags: { has: filters.query } },
    ];
  }

  return where;
}

function buildOrderBy(sort: 'updated' | 'created' | 'title'): Prisma.SecretOrderByWithRelationInput[] {
  if (sort === 'title') return [{ title: 'asc' }, { id: 'asc' }];
  if (sort === 'created') return [{ createdAt: 'desc' }, { id: 'asc' }];
  return [{ updatedAt: 'desc' }, { id: 'asc' }];
}

secretsRouter.get('/', async (req, res) => {
  const { user } = getAuth(req);
  const filters = parseQuery(listSecretsQuerySchema, req);

  const items = await prisma.secret.findMany({
    where: buildWhere(user.id, getWorkspaceId(req), filters),
    orderBy: buildOrderBy(filters.sort),
    take: filters.limit + 1,
    ...(filters.cursor ? { cursor: { id: filters.cursor }, skip: 1 } : {}),
  });

  const hasMore = items.length > filters.limit;
  const page = hasMore ? items.slice(0, filters.limit) : items;

  res.json({
    items: page.map(toSecretDto),
    nextCursor: hasMore ? (page[page.length - 1]?.id ?? null) : null,
    vaultKeyVersion: user.vaultKeyVersion,
  });
});

secretsRouter.post('/', async (req, res) => {
  const { user } = getAuth(req);
  const workspaceId = getWorkspaceId(req);
  const body = parseBody(createSecretSchema, req);
  await assertFolderOwned(body.folderId, user.id, workspaceId);

  const secret = await prisma.secret.create({
    data: {
      userId: user.id,
      workspaceId,
      title: body.title,
      category: body.category,
      folderId: body.folderId ?? null,
      tags: body.tags,
      isFavorite: body.isFavorite,
      encVersion: body.encVersion,
      keyVersion: body.keyVersion,
      nonce: body.nonce,
      ciphertext: body.ciphertext,
    },
  });

  await recordActivity({
    userId: user.id,
    type: 'SECRET_CREATED',
    targetType: 'secret',
    targetId: secret.id,
    targetLabel: secret.title,
    req,
  });

  res.status(201).json({ secret: toSecretDto(secret) });
});

secretsRouter.post('/bulk', async (req, res) => {
  const { user } = getAuth(req);
  const workspaceId = getWorkspaceId(req);
  const body = parseBody(bulkCreateSecretsSchema, req);

  const folderIds = [...new Set(body.items.map((item) => item.folderId).filter(Boolean))] as string[];
  for (const folderId of folderIds) await assertFolderOwned(folderId, user.id, workspaceId);

  const created = await prisma.secret.createManyAndReturn({
    data: body.items.map((item) => ({
      userId: user.id,
      workspaceId,
      title: item.title,
      category: item.category,
      folderId: item.folderId ?? null,
      tags: item.tags,
      isFavorite: item.isFavorite,
      encVersion: item.encVersion,
      keyVersion: item.keyVersion,
      nonce: item.nonce,
      ciphertext: item.ciphertext,
    })),
  });

  await recordActivity({
    userId: user.id,
    type: body.source === 'manual' ? 'SECRET_CREATED' : 'SECRETS_IMPORTED',
    targetType: 'secret',
    targetLabel: `${created.length} item${created.length === 1 ? '' : 's'}`,
    req,
  });

  res.status(201).json({ items: created.map(toSecretDto), created: created.length });
});

/** Trash listing. Registered before /:id so "trash" is never parsed as an id. */
secretsRouter.get('/trash', async (req, res) => {
  const { user } = getAuth(req);
  const workspaceId = getWorkspaceId(req);
  await purgeExpiredTrash(user.id, workspaceId);

  const items = await prisma.secret.findMany({
    where: { userId: user.id, workspaceId, deletedAt: { not: null } },
    orderBy: { deletedAt: 'desc' },
  });

  res.json({ items: items.map(toSecretDto), retentionDays: TRASH_RETENTION_DAYS });
});

/** Empties the trash in one call - every trashed row is hard-deleted. */
secretsRouter.delete('/trash', async (req, res) => {
  const { user } = getAuth(req);
  const result = await prisma.secret.deleteMany({
    where: { userId: user.id, workspaceId: getWorkspaceId(req), deletedAt: { not: null } },
  });

  if (result.count > 0) {
    await recordActivity({
      userId: user.id,
      type: 'SECRET_PURGED',
      targetType: 'secret',
      targetLabel: `${result.count} item${result.count === 1 ? '' : 's'}`,
      req,
    });
  }

  res.json({ purged: result.count });
});

secretsRouter.get('/:id', async (req, res) => {
  const { user } = getAuth(req);
  const secret = await findOwnedSecret(parseIdParam(req), user.id, getWorkspaceId(req));
  res.json({ secret: toSecretDto(secret) });
});

secretsRouter.patch('/:id', async (req, res) => {
  const { user } = getAuth(req);
  const id = parseIdParam(req);
  const workspaceId = getWorkspaceId(req);
  const body = parseBody(updateSecretSchema, req);
  const existing = await findOwnedSecret(id, user.id, workspaceId);

  // Moving to another workspace: the target must be owned by the same user.
  // Folders are workspace-local, so the move detaches the secret (an explicit
  // folderId in the body is validated against the *destination* workspace).
  const moveTarget = body.workspaceId !== undefined && body.workspaceId !== existing.workspaceId
    ? body.workspaceId
    : undefined;
  if (moveTarget) {
    const target = await prisma.workspace.findFirst({
      where: { id: moveTarget, userId: user.id },
      select: { id: true },
    });
    if (!target) throw ApiError.notFound('That organisation does not exist.');
  }
  const effectiveWorkspaceId = moveTarget ?? existing.workspaceId;

  if (body.folderId !== undefined) await assertFolderOwned(body.folderId, user.id, effectiveWorkspaceId);

  const payloadChanged = body.ciphertext !== undefined && body.nonce !== undefined;

  const data: Prisma.SecretUpdateInput = {};
  if (body.title !== undefined) data.title = body.title;
  if (body.category !== undefined) data.category = body.category;
  if (moveTarget) data.workspace = { connect: { id: moveTarget } };
  if (moveTarget && body.folderId === undefined) {
    data.folder = { disconnect: true };
  } else if (body.folderId !== undefined) {
    data.folder = body.folderId ? { connect: { id: body.folderId } } : { disconnect: true };
  }
  if (body.tags !== undefined) data.tags = body.tags;
  if (body.isFavorite !== undefined) data.isFavorite = body.isFavorite;

  if (payloadChanged) {
    data.nonce = body.nonce;
    data.ciphertext = body.ciphertext;
    data.keyVersion = body.keyVersion;
    if (body.encVersion !== undefined) data.encVersion = body.encVersion;
    data.version = { increment: 1 };
  }

  const [secret] = await prisma.$transaction([
    prisma.secret.update({ where: { id: existing.id }, data }),
    // Attachments carry a denormalised workspaceId - keep it in sync on moves.
    ...(moveTarget
      ? [prisma.attachment.updateMany({ where: { secretId: existing.id }, data: { workspaceId: moveTarget } })]
      : []),
    // Snapshot the *previous* encrypted payload before overwriting it.
    ...(payloadChanged
      ? [
          prisma.secretVersion.create({
            data: {
              secretId: existing.id,
              userId: user.id,
              version: existing.version,
              title: existing.title,
              category: existing.category,
              encVersion: existing.encVersion,
              keyVersion: existing.keyVersion,
              nonce: existing.nonce,
              ciphertext: existing.ciphertext,
            },
          }),
        ]
      : []),
  ]);

  if (payloadChanged) await pruneVersions(existing.id);

  await recordActivity({
    userId: user.id,
    type: 'SECRET_UPDATED',
    targetType: 'secret',
    targetId: secret.id,
    targetLabel: secret.title,
    req,
  });

  res.json({ secret: toSecretDto(secret) });
});

/** Soft-delete: the row moves to the trash and is purged after retention. */
secretsRouter.delete('/:id', async (req, res) => {
  const { user } = getAuth(req);
  const id = parseIdParam(req);
  const secret = await findOwnedSecret(id, user.id, getWorkspaceId(req));

  await prisma.secret.update({ where: { id: secret.id }, data: { deletedAt: new Date() } });
  await recordActivity({
    userId: user.id,
    type: 'SECRET_TRASHED',
    targetType: 'secret',
    targetId: secret.id,
    targetLabel: secret.title,
    req,
  });

  res.status(204).end();
});

secretsRouter.post('/:id/restore', async (req, res) => {
  const { user } = getAuth(req);
  const secret = await findTrashedSecret(parseIdParam(req), user.id, getWorkspaceId(req));

  const restored = await prisma.secret.update({
    where: { id: secret.id },
    data: { deletedAt: null },
  });

  await recordActivity({
    userId: user.id,
    type: 'SECRET_RESTORED',
    targetType: 'secret',
    targetId: secret.id,
    targetLabel: secret.title,
    req,
  });

  res.json({ secret: toSecretDto(restored) });
});

/** Hard delete from the trash - cascades versions and attachments. */
secretsRouter.delete('/:id/permanent', async (req, res) => {
  const { user } = getAuth(req);
  const secret = await findTrashedSecret(parseIdParam(req), user.id, getWorkspaceId(req));

  await prisma.secret.delete({ where: { id: secret.id } });
  await recordActivity({
    userId: user.id,
    type: 'SECRET_PURGED',
    targetType: 'secret',
    targetId: secret.id,
    targetLabel: secret.title,
    req,
  });

  res.status(204).end();
});

secretsRouter.get('/:id/versions', async (req, res) => {
  const { user } = getAuth(req);
  const secret = await findOwnedSecret(parseIdParam(req), user.id, getWorkspaceId(req));

  const versions = await prisma.secretVersion.findMany({
    where: { secretId: secret.id, userId: user.id },
    orderBy: { version: 'desc' },
    take: MAX_VERSIONS_PER_SECRET,
  });

  res.json({
    current: toSecretDto(secret),
    items: versions.map(toSecretVersionDto),
  });
});

secretsRouter.post('/:id/versions/:versionId/restore', async (req, res) => {
  const { user } = getAuth(req);
  const secret = await findOwnedSecret(parseIdParam(req), user.id, getWorkspaceId(req));
  const versionId = parseIdParam(req, 'versionId');

  const version = await prisma.secretVersion.findFirst({
    where: { id: versionId, secretId: secret.id, userId: user.id },
  });
  if (!version) throw ApiError.notFound('That version no longer exists.');

  const [restored] = await prisma.$transaction([
    prisma.secret.update({
      where: { id: secret.id },
      data: {
        title: version.title,
        category: version.category,
        encVersion: version.encVersion,
        keyVersion: version.keyVersion,
        nonce: version.nonce,
        ciphertext: version.ciphertext,
        version: { increment: 1 },
      },
    }),
    // The payload being replaced becomes a version of its own, so restoring is
    // itself undoable.
    prisma.secretVersion.create({
      data: {
        secretId: secret.id,
        userId: user.id,
        version: secret.version,
        title: secret.title,
        category: secret.category,
        encVersion: secret.encVersion,
        keyVersion: secret.keyVersion,
        nonce: secret.nonce,
        ciphertext: secret.ciphertext,
      },
    }),
  ]);

  await pruneVersions(secret.id);
  await recordActivity({
    userId: user.id,
    type: 'SECRET_RESTORED',
    targetType: 'secret',
    targetId: secret.id,
    targetLabel: restored.title,
    req,
  });

  res.json({ secret: toSecretDto(restored) });
});

// ---------------------------------------------------------------------------
// Encrypted file attachments (.env files, PEM/PPK keys, keystores, VPN configs).
// The server stores ciphertext only; `fileName`/`size`/`mimeType` stay plaintext
// for display, exactly like a secret's title.
// ---------------------------------------------------------------------------

secretsRouter.get('/:id/attachments', async (req, res) => {
  const { user } = getAuth(req);
  const secret = await findOwnedSecret(parseIdParam(req), user.id, getWorkspaceId(req));

  const items = await prisma.attachment.findMany({
    where: { secretId: secret.id, userId: user.id },
    orderBy: { createdAt: 'asc' },
  });

  res.json({ items: items.map((item) => toAttachmentDto(item)) });
});

secretsRouter.post('/:id/attachments', async (req, res) => {
  const { user } = getAuth(req);
  const secret = await findOwnedSecret(parseIdParam(req), user.id, getWorkspaceId(req));
  const body = parseBody(createAttachmentSchema, req);

  const count = await prisma.attachment.count({ where: { secretId: secret.id } });
  if (count >= MAX_ATTACHMENTS_PER_SECRET) {
    throw ApiError.badRequest(`A secret can hold at most ${MAX_ATTACHMENTS_PER_SECRET} files.`);
  }

  const attachment = await prisma.attachment.create({
    data: {
      userId: user.id,
      // Attachments live wherever their secret lives - the denormalised scope
      // stays in sync with the parent, including workspace moves.
      workspaceId: secret.workspaceId,
      secretId: secret.id,
      fileName: body.fileName,
      mimeType: body.mimeType ?? null,
      size: body.size,
      encVersion: body.encVersion,
      keyVersion: body.keyVersion,
      nonce: body.nonce,
      ciphertext: body.ciphertext,
    },
  });

  await recordActivity({
    userId: user.id,
    type: 'ATTACHMENT_UPLOADED',
    targetType: 'attachment',
    targetId: attachment.id,
    targetLabel: `${secret.title} / ${attachment.fileName}`,
    req,
  });

  res.status(201).json({ attachment: toAttachmentDto(attachment) });
});

/** Download returns the ciphertext blob; decryption happens in the browser. */
secretsRouter.get('/:id/attachments/:attachmentId', async (req, res) => {
  const { user } = getAuth(req);
  const secret = await findOwnedSecret(parseIdParam(req), user.id, getWorkspaceId(req));
  const attachmentId = parseIdParam(req, 'attachmentId');

  const attachment = await prisma.attachment.findFirst({
    where: { id: attachmentId, secretId: secret.id, userId: user.id },
  });
  if (!attachment) throw ApiError.notFound('That file no longer exists.');

  res.json({ attachment: toAttachmentDto(attachment, { includeCiphertext: true }) });
});

secretsRouter.delete('/:id/attachments/:attachmentId', async (req, res) => {
  const { user } = getAuth(req);
  const secret = await findOwnedSecret(parseIdParam(req), user.id, getWorkspaceId(req));
  const attachmentId = parseIdParam(req, 'attachmentId');

  const attachment = await prisma.attachment.findFirst({
    where: { id: attachmentId, secretId: secret.id, userId: user.id },
  });
  if (!attachment) throw ApiError.notFound('That file no longer exists.');

  await prisma.attachment.delete({ where: { id: attachment.id } });
  await recordActivity({
    userId: user.id,
    type: 'ATTACHMENT_DELETED',
    targetType: 'attachment',
    targetId: attachment.id,
    targetLabel: `${secret.title} / ${attachment.fileName}`,
    req,
  });

  res.status(204).end();
});

/** Dedicated favourites listing used by the Favourites page. */
export const favoritesRouter = Router();

favoritesRouter.use(requireAuth, requireVerifiedEmail, csrfGuard, workspaceScope);

favoritesRouter.get('/', async (req, res) => {
  const { user } = getAuth(req);
  const filters = parseQuery(listSecretsQuerySchema, req);

  const items = await prisma.secret.findMany({
    where: { ...buildWhere(user.id, getWorkspaceId(req), filters), isFavorite: true },
    orderBy: buildOrderBy(filters.sort),
    take: filters.limit,
  });

  res.json({ items: items.map(toSecretDto), nextCursor: null, vaultKeyVersion: user.vaultKeyVersion });
});

/** Keeps history bounded: only the newest N encrypted snapshots are retained. */
async function pruneVersions(secretId: string): Promise<void> {
  const keep = await prisma.secretVersion.findMany({
    where: { secretId },
    orderBy: { version: 'desc' },
    take: MAX_VERSIONS_PER_SECRET,
    select: { id: true },
  });

  await prisma.secretVersion.deleteMany({
    where: { secretId, id: { notIn: keep.map((row) => row.id) } },
  });
}
