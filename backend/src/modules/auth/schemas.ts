import { z } from 'zod';
import {
  authVerifierSchema,
  ecdhPublicKeySchema,
  emailSchema,
  kdfSchema,
  nameSchema,
  serverWrappedVaultKeySchema,
  wrappedVaultKeySchema,
} from '../../utils/validation.js';

export const preloginSchema = z.object({
  email: emailSchema,
});

export const signupSchema = z.object({
  email: emailSchema,
  name: nameSchema.optional(),
  authVerifier: authVerifierSchema,
  kdf: kdfSchema,
  wrappedVaultKey: wrappedVaultKeySchema,
  /** Same key, ECDH-wrapped to the server escrow key so resets can recover it. */
  serverWrappedVaultKey: serverWrappedVaultKeySchema.optional(),
  /**
   * Honeypot: the signup form renders a visually-hidden "website" input that
   * humans never fill and dumb bots always do. Any non-empty value means the
   * submitter is automated - rejected without revealing why.
   */
  website: z.string().max(200).optional(),
});

export const loginSchema = z.object({
  email: emailSchema,
  authVerifier: authVerifierSchema,
});

/** Second step of login when the account has TOTP 2FA enabled. */
export const loginMfaSchema = z.object({
  mfaToken: z.string().min(32).max(1024),
  code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code from your authenticator app.'),
});

const totpCodeSchema = z.object({
  code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code from your authenticator app.'),
});

export const totpConfirmSchema = totpCodeSchema;
export const totpDisableSchema = totpCodeSchema;

export const forgotPasswordSchema = z.object({
  email: emailSchema,
});

export const resetPrepareSchema = z.object({
  token: z.string().min(16).max(256),
  clientPublicKey: ecdhPublicKeySchema,
});

export const resetPasswordSchema = z
  .object({
    token: z.string().min(16).max(256),
    authVerifier: authVerifierSchema,
    kdf: kdfSchema,
    wrappedVaultKey: wrappedVaultKeySchema,
    /** Fresh escrow for whatever key now protects the vault. */
    serverWrappedVaultKey: serverWrappedVaultKeySchema.optional(),
    /** True when the client recovered the existing key via reset-prepare. */
    vaultKeyPreserved: z.boolean().default(false),
    acknowledgeVaultLoss: z.boolean().optional(),
  })
  .superRefine((body, ctx) => {
    // Only the destructive path needs an explicit acknowledgement.
    if (!body.vaultKeyPreserved && body.acknowledgeVaultLoss !== true) {
      ctx.addIssue({
        code: 'custom',
        path: ['acknowledgeVaultLoss'],
        message: 'You must acknowledge that existing vault items cannot be decrypted after a reset.',
      });
    }
  });

export const changePasswordSchema = z.object({
  currentAuthVerifier: authVerifierSchema,
  newAuthVerifier: authVerifierSchema,
  kdf: kdfSchema,
  /** Same vault key, re-wrapped with the key derived from the new password. */
  newWrappedVaultKey: wrappedVaultKeySchema,
  revokeOtherSessions: z.boolean().default(true),
});

export const verifyEmailSchema = z.object({
  token: z.string().min(16).max(256),
});

/** The 6-digit code emailed at signup / on resend, typed in while signed in. */
export const verifyEmailCodeSchema = z.object({
  code: z.string().regex(/^\d{6}$/, 'Enter the 6-digit code from the verification email.'),
});

export const deleteAccountSchema = z.object({
  authVerifier: authVerifierSchema,
  confirm: z.literal('DELETE MY VAULT', { error: 'Type the confirmation phrase exactly to continue.' }),
});

/** The extension exchanges a one-time link code (from /auth/extension-link) for a session. */
export const extensionSessionSchema = z.object({
  code: z.string().min(32).max(256),
});
