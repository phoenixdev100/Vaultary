import type {
  ActivityEvent,
  Attachment,
  Folder,
  Secret,
  SecretVersion,
  Session,
  User,
  Workspace,
} from '../generated/prisma/client.js';

/** Everything the browser needs to unlock the vault - never the vault key itself. */
export function toUserDto(user: User) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    emailVerified: user.emailVerifiedAt !== null,
    totpEnabled: user.totpEnabled,
    autoLockMinutes: user.autoLockMinutes,
    theme: user.theme,
    vaultKeyVersion: user.vaultKeyVersion,
    wrappedVaultKey: user.wrappedVaultKey,
    sharePublicKey: user.sharePublicKey,
    sharePrivateKeyWrapped: user.sharePrivateKeyWrapped,
    kdf: {
      algorithm: user.kdfAlgorithm,
      memoryKiB: user.kdfMemoryKiB,
      iterations: user.kdfIterations,
      parallelism: user.kdfParallelism,
    },
    passwordChangedAt: user.passwordChangedAt.toISOString(),
    createdAt: user.createdAt.toISOString(),
  };
}

export function toWorkspaceDto(workspace: Workspace) {
  return {
    id: workspace.id,
    name: workspace.name,
    color: workspace.color,
    isDefault: workspace.isDefault,
    createdAt: workspace.createdAt.toISOString(),
    updatedAt: workspace.updatedAt.toISOString(),
  };
}

export function toSecretDto(secret: Secret) {
  return {
    id: secret.id,
    title: secret.title,
    category: secret.category,
    tags: secret.tags,
    isFavorite: secret.isFavorite,
    folderId: secret.folderId,
    workspaceId: secret.workspaceId,
    encVersion: secret.encVersion,
    keyVersion: secret.keyVersion,
    nonce: secret.nonce,
    ciphertext: secret.ciphertext,
    version: secret.version,
    deletedAt: secret.deletedAt ? secret.deletedAt.toISOString() : null,
    createdAt: secret.createdAt.toISOString(),
    updatedAt: secret.updatedAt.toISOString(),
  };
}

export function toAttachmentDto(attachment: Attachment, { includeCiphertext = false } = {}) {
  return {
    id: attachment.id,
    secretId: attachment.secretId,
    fileName: attachment.fileName,
    mimeType: attachment.mimeType,
    size: attachment.size,
    encVersion: attachment.encVersion,
    keyVersion: attachment.keyVersion,
    nonce: attachment.nonce,
    ...(includeCiphertext ? { ciphertext: attachment.ciphertext } : {}),
    createdAt: attachment.createdAt.toISOString(),
  };
}

export function toSecretVersionDto(version: SecretVersion) {
  return {
    id: version.id,
    secretId: version.secretId,
    version: version.version,
    title: version.title,
    category: version.category,
    encVersion: version.encVersion,
    keyVersion: version.keyVersion,
    nonce: version.nonce,
    ciphertext: version.ciphertext,
    createdAt: version.createdAt.toISOString(),
  };
}

export function toFolderDto(folder: Folder & { _count?: { secrets: number; children?: number } }) {
  return {
    id: folder.id,
    name: folder.name,
    color: folder.color,
    parentId: folder.parentId,
    secretCount: folder._count?.secrets ?? 0,
    subfolderCount: folder._count?.children ?? 0,
    createdAt: folder.createdAt.toISOString(),
    updatedAt: folder.updatedAt.toISOString(),
  };
}

export function toActivityDto(event: ActivityEvent) {
  return {
    id: event.id,
    type: event.type,
    targetType: event.targetType,
    targetId: event.targetId,
    targetLabel: event.targetLabel,
    ipLabel: event.ipLabel,
    userAgent: event.userAgent,
    createdAt: event.createdAt.toISOString(),
  };
}

export function toSessionDto(session: Session, currentSessionId: string) {
  return {
    id: session.id,
    current: session.id === currentSessionId,
    userAgent: session.userAgent,
    ipLabel: session.ipLabel,
    country: session.country,
    createdAt: session.createdAt.toISOString(),
    lastSeenAt: session.lastSeenAt.toISOString(),
    expiresAt: session.expiresAt.toISOString(),
  };
}
