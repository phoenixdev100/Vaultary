import { z } from 'zod';
import {
  MAX_ATTACHMENT_BYTES,
  MAX_SECRETS_PER_IMPORT,
  MAX_SECRETS_PER_PAGE,
} from '../../config/constants.js';
import {
  base64,
  categorySchema,
  ciphertextSchema,
  idSchema,
  nonceSchema,
  tagsSchema,
  titleSchema,
} from '../../utils/validation.js';

const payloadFields = {
  encVersion: z.literal(1).default(1),
  keyVersion: z.number().int().min(1).max(1_000_000),
  nonce: nonceSchema,
  ciphertext: ciphertextSchema,
};

export const createSecretSchema = z.object({
  title: titleSchema,
  category: categorySchema,
  folderId: idSchema.nullish(),
  tags: tagsSchema,
  isFavorite: z.boolean().default(false),
  ...payloadFields,
});

export const updateSecretSchema = z
  .object({
    title: titleSchema.optional(),
    category: categorySchema.optional(),
    folderId: idSchema.nullish(),
    tags: tagsSchema.optional(),
    isFavorite: z.boolean().optional(),
    encVersion: z.literal(1).optional(),
    keyVersion: z.number().int().min(1).max(1_000_000).optional(),
    nonce: nonceSchema.optional(),
    ciphertext: ciphertextSchema.optional(),
  })
  .refine(
    (value) =>
      (value.nonce === undefined && value.ciphertext === undefined) ||
      (value.nonce !== undefined && value.ciphertext !== undefined && value.keyVersion !== undefined),
    { error: 'An encrypted payload must include nonce, ciphertext and keyVersion together.' },
  )
  .refine((value) => Object.keys(value).length > 0, { error: 'Nothing to update.' });

export const bulkCreateSecretsSchema = z.object({
  items: z.array(createSecretSchema).min(1).max(MAX_SECRETS_PER_IMPORT),
  source: z.enum(['env-import', 'csv-import', 'backup-restore', 'manual']).default('manual'),
});

export const listSecretsQuerySchema = z.object({
  query: z.string().trim().max(200).optional(),
  category: categorySchema.optional(),
  folderId: z.union([idSchema, z.literal('none')]).optional(),
  tag: z.string().trim().min(1).max(32).optional(),
  favorite: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => (value === undefined ? undefined : value === 'true')),
  sort: z.enum(['updated', 'created', 'title']).default('updated'),
  limit: z.coerce.number().int().min(1).max(MAX_SECRETS_PER_PAGE).default(50),
  cursor: idSchema.optional(),
});

export const restoreVersionSchema = z.object({
  versionId: idSchema,
});

/**
 * Encrypted file upload. `size` is the *plaintext* byte count so the client can
 * display it and the server can enforce the 2 MiB budget without decrypting.
 * Ciphertext budget: ceil(2 MiB + tag) in base64 ~ 2.8 MB.
 */
export const createAttachmentSchema = z.object({
  fileName: z
    .string()
    .trim()
    .min(1, 'File name is required')
    .max(255)
    .refine((name) => !/[/\\]/.test(name) && !/[\p{Cc}]/u.test(name), {
      error: 'File name must not contain path separators or control characters',
    }),
  mimeType: z.string().trim().max(100).optional(),
  size: z.number().int().min(0).max(MAX_ATTACHMENT_BYTES),
  encVersion: z.literal(1).default(1),
  keyVersion: z.number().int().min(1).max(1_000_000),
  nonce: nonceSchema,
  ciphertext: base64(3_000_000, 'file ciphertext'),
});
