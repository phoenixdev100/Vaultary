/**
 * Client-side KDF defaults (OWASP Argon2id minimum: 19 MiB, t=2, p=1).
 * Must stay in sync with `frontend/src/lib/crypto/kdf.ts`.
 */
export const DEFAULT_KDF = {
  algorithm: 'argon2id',
  memoryKiB: 19_456,
  iterations: 2,
  parallelism: 1,
} as const;

/** Reset links are deliberately short-lived - request a fresh one if expired. */
export const PASSWORD_RESET_TTL_MS = 10 * 60 * 1000;
export const EMAIL_VERIFICATION_TTL_MS = 24 * 60 * 60 * 1000;
/// Signed proof that the password half of login succeeded - kept short so a
/// leaked token has almost no window; also single-use via VerificationToken.
export const MFA_TOKEN_TTL_MS = 5 * 60 * 1000;

/// One-time code the web app hands to the browser extension during pairing.
/// Two minutes is plenty for a redirect hop; also single-use.
export const EXTENSION_LINK_TTL_MS = 2 * 60 * 1000;

export const MAX_SECRETS_PER_IMPORT = 200;
export const MAX_VERSIONS_PER_SECRET = 20;
export const MAX_SECRETS_PER_PAGE = 100;
export const MAX_FOLDERS_PER_USER = 100;
/// Folder nesting depth: root -> child -> grandchild (3 levels) keeps the
/// picker readable and bounds the ancestor/descendant walks on move checks.
export const MAX_FOLDER_DEPTH = 3;

/// Encrypted file attachments on secrets (.env, PEM/PPK keys, keystores…).
/// 2 MiB of plaintext ≈ 2.7 MB base64 - inside Vercel's ~4.5 MB function
/// request limit and this app's 10mb JSON body cap.
export const MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024;
export const MAX_ATTACHMENTS_PER_SECRET = 20;

/// Days a trashed secret stays recoverable before lazy purge.
export const TRASH_RETENTION_DAYS = 30;
