import { randomInt } from 'node:crypto';
import { Router } from 'express';
import {
  DEFAULT_KDF,
  EMAIL_VERIFICATION_TTL_MS,
  EXTENSION_LINK_TTL_MS,
  MFA_TOKEN_TTL_MS,
  PASSWORD_RESET_TTL_MS,
} from '../../config/constants.js';
import { env, isProduction } from '../../config/env.js';
import { logger } from '../../config/logger.js';
import { prisma } from '../../db/prisma.js';
import { csrfGuard, getAuth, requireAuth, requireVerifiedEmail } from '../../middleware/auth.js';
import { dbRateLimit, emailAndIpIdentifier, ipIdentifier, userIdentifier } from '../../middleware/rateLimit.js';
import { recordActivity } from '../../services/activity.js';
import { isDisposableEmail } from '../../services/disposableEmail.js';
import { mailer, passwordResetEmail, verifyEmailEmail, welcomeEmail } from '../../services/mailer.js';
import {
  clearSessionCookie,
  createSession,
  deriveCsrfToken,
  listSessions,
  revokeOtherSessions,
  revokeSession,
  setSessionCookie,
  SESSION_COOKIE,
} from '../../services/session.js';
import {
  dummyVerify,
  generateToken,
  hashAuthVerifier,
  hashToken,
  verifyAuthVerifier,
} from '../../utils/crypto.js';
import { toSessionDto, toUserDto } from '../../utils/dto.js';
import { ApiError } from '../../utils/http.js';
import { parseBody, parseIdParam } from '../../utils/request.js';
import {
  serverEscrowPublicKey,
  unwrapEscrowedVaultKey,
  wrapVaultKeyForClient,
} from '../../utils/vaultEscrow.js';
import {
  changePasswordSchema,
  extensionSessionSchema,
  forgotPasswordSchema,
  loginMfaSchema,
  loginSchema,
  preloginSchema,
  resetPasswordSchema,
  resetPrepareSchema,
  signupSchema,
  totpConfirmSchema,
  totpDisableSchema,
  verifyEmailSchema,
  verifyEmailCodeSchema,
} from './schemas.js';
import {
  generateTotpSecret,
  otpauthUrl,
  signMfaToken,
  unwrapTotpSecret,
  verifyMfaToken,
  verifyTotp,
  wrapTotpSecret,
} from '../../utils/totp.js';

export const authRouter = Router();

/**
 * Temp/disposable mailboxes are refused outright: they defeat verification,
 * password reset and any abuse audit trail. Applies to signup and login -
 * an existing disposable-domain account (pre-blocklist) gets the same answer.
 */
function rejectDisposableEmail(email: string): void {
  if (isDisposableEmail(email)) {
    throw new ApiError(
      400,
      'disposable_email',
      'Temporary or disposable email addresses are not allowed. Please use your real email address.',
    );
  }
}

/**
 * The server's escrow public key (raw P-256 point). Clients encrypt the vault
 * key to it at signup so an email-verified reset can recover the same key.
 * Public by design - only the matching private scalar can open the blobs.
 */
authRouter.get(
  '/server-key',
  dbRateLimit({ scope: 'server-key', limit: 120, windowMs: 60 * 60 * 1000, identifier: ipIdentifier }),
  (_req, res) => {
    res.json({ publicKey: serverEscrowPublicKey(), algorithm: 'ECDH-P-256+AES-256-GCM' });
  },
);

/**
 * The browser needs the account's KDF parameters *before* it can derive the
 * authentication verifier. Unknown addresses get the current defaults back so
 * this endpoint cannot be used to enumerate registered users.
 */
authRouter.post(
  '/prelogin',
  dbRateLimit({ scope: 'prelogin', limit: 60, windowMs: 15 * 60 * 1000, identifier: ipIdentifier }),
  async (req, res) => {
    const { email } = parseBody(preloginSchema, req);
    rejectDisposableEmail(email);
    const user = await prisma.user.findUnique({
      where: { email },
      select: { kdfAlgorithm: true, kdfMemoryKiB: true, kdfIterations: true, kdfParallelism: true },
    });

    res.json({
      kdf: user
        ? {
            algorithm: user.kdfAlgorithm,
            memoryKiB: user.kdfMemoryKiB,
            iterations: user.kdfIterations,
            parallelism: user.kdfParallelism,
          }
        : DEFAULT_KDF,
    });
  },
);

authRouter.post(
  '/signup',
  dbRateLimit({ scope: 'signup', limit: 10, windowMs: 60 * 60 * 1000, identifier: ipIdentifier }),
  async (req, res) => {
    const body = parseBody(signupSchema, req);
    // Honeypot tripped: answer like any other bad request, don't tip off bots.
    if (body.website) {
      throw ApiError.badRequest('Signup could not be completed. Please try again.');
    }
    rejectDisposableEmail(body.email);

    const existing = await prisma.user.findUnique({ where: { email: body.email }, select: { id: true } });
    if (existing) {
      throw ApiError.conflict('An account with that email address already exists.');
    }

    const user = await prisma.user.create({
      data: {
        email: body.email,
        name: body.name ?? null,
        authHash: await hashAuthVerifier(body.authVerifier),
        kdfAlgorithm: body.kdf.algorithm,
        kdfMemoryKiB: body.kdf.memoryKiB,
        kdfIterations: body.kdf.iterations,
        kdfParallelism: body.kdf.parallelism,
        wrappedVaultKey: body.wrappedVaultKey,
        serverWrappedVaultKey: body.serverWrappedVaultKey ?? null,
        autoLockMinutes: env.AUTO_LOCK_MINUTES,
        // Starter folders so the vault is immediately organisable.
        folders: { create: [{ name: 'Personal' }, { name: 'Development' }] },
      },
    });

    const issued = await createSession(user.id, req);
    setSessionCookie(res, issued);
    await recordActivity({ userId: user.id, type: 'SIGNUP', targetType: 'account', req });

    let emailVerification: { required: boolean; delivered: boolean; previewUrl?: string } | undefined;
    if (env.REQUIRE_EMAIL_VERIFICATION) {
      // Best-effort: a broken mail transport must never strand a fresh account.
      emailVerification = await sendVerificationEmail(user.id, user.email).catch((error) => {
        logger.warn({ err: error instanceof Error ? error.message : error }, 'verification email failed');
        return { required: true, delivered: false };
      });
    }

    // Awaited because serverless freezes the instance right after the response;
    // still best-effort - a mail hiccup never breaks signup.
    const { message: welcome } = welcomeEmail(user.email, user.name);
    await mailer.send(welcome).catch((error) => {
      logger.warn({ err: error instanceof Error ? error.message : error }, 'welcome email failed');
    });

    res.status(201).json({
      user: toUserDto(user),
      csrfToken: issued.csrfToken,
      sessionToken: issued.token,
      ...(emailVerification ? { emailVerification } : {}),
    });
  },
);

authRouter.post(
  '/login',
  dbRateLimit({
    scope: 'login',
    limit: 10,
    windowMs: 15 * 60 * 1000,
    identifier: emailAndIpIdentifier,
    message: 'Too many sign-in attempts. Please wait a few minutes and try again.',
  }),
  async (req, res) => {
    const body = parseBody(loginSchema, req);
    rejectDisposableEmail(body.email);
    const user = await prisma.user.findUnique({ where: { email: body.email } });

    if (!user) {
      // Equalise response time so a missing account is indistinguishable.
      await dummyVerify();
      throw ApiError.unauthorized('Invalid email or password.');
    }

    const valid = await verifyAuthVerifier(body.authVerifier, user.authHash);
    if (!valid) {
      throw ApiError.unauthorized('Invalid email or password.');
    }

    // Account-level 2FA: the password half is proven, so issue a short-lived
    // signed token that only the TOTP step can turn into a session. The hash
    // is persisted so the token is single-use - replaying it within its TTL
    // cannot mint additional sessions.
    if (user.totpEnabled && user.totpSecret) {
      const mfaToken = signMfaToken(user.id);
      await prisma.$transaction([
        prisma.verificationToken.deleteMany({ where: { userId: user.id, type: 'MFA_LOGIN' } }),
        prisma.verificationToken.create({
          data: {
            userId: user.id,
            type: 'MFA_LOGIN',
            tokenHash: hashToken(mfaToken),
            expiresAt: new Date(Date.now() + MFA_TOKEN_TTL_MS),
          },
        }),
      ]);
      res.json({ mfaRequired: true, mfaToken });
      return;
    }

    const issued = await createSession(user.id, req);
    setSessionCookie(res, issued);
    await recordActivity({ userId: user.id, type: 'LOGIN', targetType: 'account', req });

    res.json({ user: toUserDto(user), csrfToken: issued.csrfToken, sessionToken: issued.token });
  },
);

/**
 * Second login step for TOTP-enabled accounts. The mfaToken proves the
 * password half already succeeded within the last 5 minutes.
 */
authRouter.post(
  '/login/mfa',
  dbRateLimit({
    scope: 'login-mfa',
    limit: 10,
    windowMs: 15 * 60 * 1000,
    identifier: ipIdentifier,
    message: 'Too many code attempts. Please sign in again.',
  }),
  async (req, res) => {
    const body = parseBody(loginMfaSchema, req);
    const userId = verifyMfaToken(body.mfaToken);
    if (!userId) {
      throw ApiError.unauthorized('That sign-in attempt has expired. Please start again.');
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user?.totpEnabled || !user.totpSecret) {
      throw ApiError.unauthorized('That sign-in attempt is no longer valid.');
    }

    if (!verifyTotp(unwrapTotpSecret(user.totpSecret), body.code)) {
      throw ApiError.unauthorized('That code is not correct.');
    }

    // Consume the persisted token only after the code verifies - a mistyped
    // TOTP must not force a fresh login, but a used token can never be
    // replayed. The delete is the atomic claim, so a concurrent replay loses.
    const consumed = await prisma.verificationToken.deleteMany({
      where: {
        userId,
        type: 'MFA_LOGIN',
        tokenHash: hashToken(body.mfaToken),
        expiresAt: { gt: new Date() },
      },
    });
    if (consumed.count === 0) {
      throw ApiError.unauthorized('That sign-in attempt has expired. Please start again.');
    }

    const issued = await createSession(user.id, req);
    setSessionCookie(res, issued);
    await recordActivity({ userId: user.id, type: 'LOGIN', targetType: 'account', req });

    res.json({ user: toUserDto(user), csrfToken: issued.csrfToken, sessionToken: issued.token });
  },
);

/**
 * Issues a one-time link code for browser-extension pairing. The web app's
 * /link-extension page calls this only after the user explicitly confirms;
 * the code is hashed at rest, dies in 2 minutes, and is consumed on exchange.
 * The vault key itself never touches this endpoint - the web page wraps it
 * to the extension's ephemeral public key inside the redirect.
 */
authRouter.post(
  '/extension-link',
  requireAuth,
  requireVerifiedEmail,
  csrfGuard,
  dbRateLimit({ scope: 'extension-link', limit: 10, windowMs: 60 * 60 * 1000, identifier: userIdentifier }),
  async (req, res) => {
    const { user } = getAuth(req);
    const code = generateToken(32);
    // One live link code per account at a time.
    await prisma.$transaction([
      prisma.verificationToken.deleteMany({ where: { userId: user.id, type: 'EXTENSION_LINK' } }),
      prisma.verificationToken.create({
        data: {
          userId: user.id,
          type: 'EXTENSION_LINK',
          tokenHash: hashToken(code),
          expiresAt: new Date(Date.now() + EXTENSION_LINK_TTL_MS),
        },
      }),
    ]);
    res.json({ code, expiresInMs: EXTENSION_LINK_TTL_MS });
  },
);

/**
 * The extension exchanges its link code for a real session. The code proves
 * the user confirmed pairing on the web app moments ago; deleting it is the
 * atomic claim so a copied code can never mint a second session. Sessions
 * minted here are ordinary Bearer sessions - revocable like any other.
 */
authRouter.post(
  '/extension-session',
  dbRateLimit({ scope: 'extension-session', limit: 20, windowMs: 15 * 60 * 1000, identifier: ipIdentifier }),
  async (req, res) => {
    const body = parseBody(extensionSessionSchema, req);
    const record = await prisma.verificationToken.findUnique({
      where: { tokenHash: hashToken(body.code) },
    });

    if (!record || record.type !== 'EXTENSION_LINK' || record.expiresAt <= new Date()) {
      throw ApiError.unauthorized('That link code is invalid or has expired.');
    }
    const consumed = await prisma.verificationToken.deleteMany({ where: { id: record.id } });
    if (consumed.count === 0) {
      throw ApiError.unauthorized('That link code is invalid or has expired.');
    }

    const user = await prisma.user.findUnique({ where: { id: record.userId } });
    if (!user) {
      throw ApiError.unauthorized('That link code is invalid or has expired.');
    }

    const issued = await createSession(user.id, req);
    // No cookie is set - the extension is a Bearer client; the token travels
    // in the JSON body only.
    await recordActivity({ userId: user.id, type: 'LOGIN', targetType: 'session', targetId: issued.session.id, req });
    res.json({ sessionToken: issued.token, user: toUserDto(user) });
  },
);

authRouter.get('/me', requireAuth, (req, res) => {
  const { user, session } = getAuth(req);
  const rawToken = (req.cookies as Record<string, string>)[SESSION_COOKIE] ?? '';

  res.json({
    user: toUserDto(user),
    // Bearer sessions carry no cookie, so there is no ambient token to derive
    // a CSRF token from - return null rather than a junk derived value.
    csrfToken: rawToken === '' ? null : deriveCsrfToken(rawToken),
    session: toSessionDto(session, session.id),
  });
});

authRouter.post('/logout', requireAuth, csrfGuard, async (req, res) => {
  const { user, session } = getAuth(req);
  await revokeSession(session.id, user.id);
  clearSessionCookie(res);
  await recordActivity({ userId: user.id, type: 'LOGOUT', targetType: 'session', targetId: session.id, req });
  res.status(204).end();
});

authRouter.post(
  '/forgot-password',
  dbRateLimit({ scope: 'forgot-password', limit: 5, windowMs: 60 * 60 * 1000, identifier: emailAndIpIdentifier }),
  async (req, res) => {
    const { email } = parseBody(forgotPasswordSchema, req);
    rejectDisposableEmail(email);
    const user = await prisma.user.findUnique({ where: { email }, select: { id: true, email: true } });

    let previewUrl: string | undefined;
    let delivered: boolean | undefined;

    if (user) {
      const token = generateToken(32);
      // Invalidate prior links and create the new one atomically - two racing
      // requests cannot leave two live reset tokens behind.
      await prisma.$transaction([
        prisma.verificationToken.updateMany({
          where: { userId: user.id, type: 'PASSWORD_RESET', usedAt: null },
          data: { usedAt: new Date() },
        }),
        prisma.verificationToken.create({
          data: {
            userId: user.id,
            type: 'PASSWORD_RESET',
            tokenHash: hashToken(token),
            expiresAt: new Date(Date.now() + PASSWORD_RESET_TTL_MS),
          },
        }),
      ]);

      const resetUrl = `${env.APP_URL}/reset-password?token=${encodeURIComponent(token)}`;
      const { message, actionUrl } = passwordResetEmail(user.email, resetUrl);
      const result = await mailer.send(message, actionUrl).catch((error) => {
        logger.warn({ err: error instanceof Error ? error.message : error }, 'reset email failed');
        return { previewUrl: undefined, delivered: false };
      });
      previewUrl = result.previewUrl;
      delivered = result.delivered;
      if (!result.delivered) {
        logger.warn({ to: user.email }, 'forgot-password: mail transport did not confirm delivery');
      }

      await recordActivity({ userId: user.id, type: 'PASSWORD_RESET_REQUESTED', targetType: 'account', req });
    }

    res.status(202).json({
      message: 'If an account exists for that address, a reset link is on its way.',
      transport: mailer.name,
      // Development observability only: outside production the caller can see
      // whether the relay actually accepted the message.
      ...(!isProduction && delivered !== undefined ? { delivered } : {}),
      // Development convenience only: with EMAIL_TRANSPORT=console nothing is
      // actually emailed, so the link is surfaced instead of faking delivery.
      ...(previewUrl && !isProduction ? { previewUrl } : {}),
    });
  },
);

/**
 * The browser needs the account's email address to rebuild the Argon2id salt
 * before it can derive new keys on the reset page. Only the holder of the
 * emailed token can read it, and the token is single-use and short-lived.
 */
authRouter.post(
  '/reset-token-info',
  dbRateLimit({ scope: 'reset-token-info', limit: 30, windowMs: 60 * 60 * 1000, identifier: ipIdentifier }),
  async (req, res) => {
    const body = parseBody(verifyEmailSchema, req);
    const record = await prisma.verificationToken.findUnique({
      where: { tokenHash: hashToken(body.token) },
      include: { user: { select: { email: true, serverWrappedVaultKey: true } } },
    });

    if (!record || record.type !== 'PASSWORD_RESET' || record.usedAt !== null || record.expiresAt <= new Date()) {
      throw new ApiError(400, 'invalid_token', 'This reset link is invalid or has expired.');
    }

    res.json({
      email: record.user.email,
      kdf: DEFAULT_KDF,
      // Tells the UI whether the vault survives this reset (escrow exists) or
      // the account predates escrow and must rotate to a fresh key.
      vaultRecoverable: record.user.serverWrappedVaultKey !== null,
    });
  },
);

/**
 * Step one of a vault-preserving reset. The token is validated but NOT
 * consumed - only the completed reset burns it - so a crash between the two
 * steps leaves the link usable. The escrowed key is unwrapped in memory and
 * re-encrypted to the browser's ephemeral public key; it never touches the
 * wire or the database in raw form.
 */
authRouter.post(
  '/reset-prepare',
  dbRateLimit({ scope: 'reset-prepare', limit: 20, windowMs: 60 * 60 * 1000, identifier: ipIdentifier }),
  async (req, res) => {
    const body = parseBody(resetPrepareSchema, req);

    const record = await prisma.verificationToken.findUnique({
      where: { tokenHash: hashToken(body.token) },
      include: { user: { select: { serverWrappedVaultKey: true } } },
    });

    if (!record || record.type !== 'PASSWORD_RESET' || record.usedAt !== null || record.expiresAt <= new Date()) {
      throw new ApiError(400, 'invalid_token', 'This reset link is invalid or has expired.');
    }

    if (!record.user.serverWrappedVaultKey) {
      res.json({ recoverable: false });
      return;
    }

    const vaultKeyRaw = unwrapEscrowedVaultKey(record.user.serverWrappedVaultKey);
    const blob = wrapVaultKeyForClient(vaultKeyRaw, body.clientPublicKey);
    vaultKeyRaw.fill(0);

    res.json({ recoverable: true, blob });
  },
);

authRouter.post(
  '/reset-password',
  dbRateLimit({ scope: 'reset-password', limit: 20, windowMs: 60 * 60 * 1000, identifier: ipIdentifier }),
  async (req, res) => {
    const body = parseBody(resetPasswordSchema, req);

    const record = await prisma.verificationToken.findUnique({
      where: { tokenHash: hashToken(body.token) },
      include: { user: true },
    });

    if (!record || record.type !== 'PASSWORD_RESET' || record.usedAt !== null || record.expiresAt <= new Date()) {
      throw new ApiError(400, 'invalid_token', 'This reset link is invalid or has expired.');
    }

    const now = new Date();
    // The preserved path only applies when the account actually has an escrow
    // blob - a forged flag cannot resurrect a key that was never escrowed.
    const preserved = body.vaultKeyPreserved && record.user.serverWrappedVaultKey !== null;
    const newKeyVersion = preserved ? record.user.vaultKeyVersion : record.user.vaultKeyVersion + 1;

    const [updatedUser] = await prisma.$transaction([
      prisma.user.update({
        where: { id: record.userId },
        data: {
          authHash: await hashAuthVerifier(body.authVerifier),
          kdfAlgorithm: body.kdf.algorithm,
          kdfMemoryKiB: body.kdf.memoryKiB,
          kdfIterations: body.kdf.iterations,
          kdfParallelism: body.kdf.parallelism,
          // Preserved: the *same* vault key re-wrapped to the new password, so
          // every existing secret stays decryptable. Otherwise a fresh random
          // key - the old one was only recoverable with the old password, and
          // the old ciphertext is kept (unreadable) rather than deleted.
          wrappedVaultKey: body.wrappedVaultKey,
          // On a rotation the old escrow wraps the OLD key - keeping it would
          // let a later reset re-wrap a dead key and orphan everything written
          // since. Preserved resets may keep it only when the client sent none.
          serverWrappedVaultKey: body.serverWrappedVaultKey ?? (preserved ? record.user.serverWrappedVaultKey : null),
          vaultKeyVersion: newKeyVersion,
          passwordChangedAt: now,
          // Email possession is the recovery root: a reset also clears 2FA so a
          // lost authenticator device cannot lock the account permanently.
          totpSecret: null,
          totpEnabled: false,
        },
      }),
      prisma.verificationToken.update({ where: { id: record.id }, data: { usedAt: now } }),
      prisma.session.updateMany({ where: { userId: record.userId, revokedAt: null }, data: { revokedAt: now } }),
      // A key rotation orphans every PRF-wrapped copy of the old vault key.
      ...(preserved ? [] : [prisma.passkey.deleteMany({ where: { userId: record.userId } })]),
    ]);

    const strandedSecrets = preserved
      ? 0
      : await prisma.secret.count({
          where: { userId: record.userId, keyVersion: { lt: newKeyVersion } },
        });

    await recordActivity({ userId: record.userId, type: 'PASSWORD_RESET_COMPLETED', targetType: 'account', req });
    if (!preserved) {
      await recordActivity({ userId: record.userId, type: 'VAULT_KEY_ROTATED', targetType: 'account', req });
    }

    res.json({
      vaultKeyVersion: updatedUser.vaultKeyVersion,
      vaultKeyPreserved: preserved,
      /** Items encrypted with the previous key: readable only with the old password. */
      strandedSecrets,
    });
  },
);

authRouter.post(
  '/change-password',
  requireAuth,
  csrfGuard,
  // Verifies the current password - a stolen session must not get unlimited
  // guesses at it.
  dbRateLimit({ scope: 'change-password', limit: 10, windowMs: 60 * 60 * 1000, identifier: userIdentifier }),
  async (req, res) => {
  const { user, session } = getAuth(req);
  const body = parseBody(changePasswordSchema, req);

  const valid = await verifyAuthVerifier(body.currentAuthVerifier, user.authHash);
  if (!valid) {
    throw ApiError.unauthorized('Your current password is incorrect.');
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      authHash: await hashAuthVerifier(body.newAuthVerifier),
      kdfAlgorithm: body.kdf.algorithm,
      kdfMemoryKiB: body.kdf.memoryKiB,
      kdfIterations: body.kdf.iterations,
      kdfParallelism: body.kdf.parallelism,
      // Same vault key, re-wrapped: every existing secret stays decryptable.
      wrappedVaultKey: body.newWrappedVaultKey,
      passwordChangedAt: new Date(),
    },
  });

  let revokedSessions = 0;
  if (body.revokeOtherSessions) {
    revokedSessions = await revokeOtherSessions(user.id, session.id);
  }

  await recordActivity({ userId: user.id, type: 'PASSWORD_CHANGED', targetType: 'account', req });

  res.json({ revokedSessions });
  },
);

authRouter.post(
  '/verify-email',
  dbRateLimit({ scope: 'verify-email', limit: 20, windowMs: 60 * 60 * 1000, identifier: ipIdentifier }),
  async (req, res) => {
    const body = parseBody(verifyEmailSchema, req);

    const record = await prisma.verificationToken.findUnique({ where: { tokenHash: hashToken(body.token) } });
    if (
      !record ||
      record.type !== 'EMAIL_VERIFICATION' ||
      record.usedAt !== null ||
      record.expiresAt <= new Date()
    ) {
      throw new ApiError(400, 'invalid_token', 'This verification link is invalid or has expired.');
    }

    const now = new Date();
    await prisma.$transaction([
      prisma.user.update({ where: { id: record.userId }, data: { emailVerifiedAt: now } }),
      prisma.verificationToken.update({ where: { id: record.id }, data: { usedAt: now } }),
    ]);

    await recordActivity({ userId: record.userId, type: 'EMAIL_VERIFIED', targetType: 'account', req });
    res.json({ verified: true });
  },
);

/**
 * In-app verification: the signed-in user types the 6-digit code from the
 * confirmation email instead of clicking the link. Auth-bound so the code
 * only ever verifies the account it was issued to - a guessed code is useless
 * against anyone else's token hash.
 */
authRouter.post(
  '/verify-email-code',
  requireAuth,
  csrfGuard,
  // Per-user: a guessed 6-digit code only helps against the account it was
  // issued to, so the budget follows the account, not the source IP.
  dbRateLimit({ scope: 'verify-email-code', limit: 10, windowMs: 60 * 60 * 1000, identifier: userIdentifier }),
  async (req, res) => {
    const { user } = getAuth(req);
    if (user.emailVerifiedAt !== null) {
      res.json({ verified: true });
      return;
    }

    const { code } = parseBody(verifyEmailCodeSchema, req);
    // Code hashes are user-scoped (see sendVerificationEmail) - a 6-digit
    // value is not globally unique, so hashing it raw would collide.
    const record = await prisma.verificationToken.findUnique({
      where: { tokenHash: hashToken(`${user.id}:${code}`) },
    });
    if (
      !record ||
      record.userId !== user.id ||
      record.type !== 'EMAIL_VERIFICATION' ||
      record.usedAt !== null ||
      record.expiresAt <= new Date()
    ) {
      throw new ApiError(400, 'invalid_code', 'That code is not correct or has expired.');
    }

    const now = new Date();
    await prisma.$transaction([
      prisma.user.update({ where: { id: user.id }, data: { emailVerifiedAt: now } }),
      prisma.verificationToken.update({ where: { id: record.id }, data: { usedAt: now } }),
    ]);

    await recordActivity({ userId: user.id, type: 'EMAIL_VERIFIED', targetType: 'account', req });
    res.json({ verified: true });
  },
);

authRouter.post(
  '/resend-verification',
  requireAuth,
  csrfGuard,
  // Per-user, not per-IP: this is the OTP-email budget, so an account cannot
  // spam its own inbox (or someone else's) regardless of where it sits.
  dbRateLimit({ scope: 'resend-verification', limit: 5, windowMs: 60 * 60 * 1000, identifier: userIdentifier }),
  async (req, res) => {
    const { user } = getAuth(req);
    if (user.emailVerifiedAt !== null) {
      res.json({ required: false, delivered: false });
      return;
    }
    res.status(202).json(await sendVerificationEmail(user.id, user.email));
  },
);

authRouter.get('/sessions', requireAuth, requireVerifiedEmail, async (req, res) => {
  const { user, session } = getAuth(req);
  const sessions = await listSessions(user.id);
  res.json({ items: sessions.map((item) => toSessionDto(item, session.id)) });
});

authRouter.delete('/sessions/:id', requireAuth, requireVerifiedEmail, csrfGuard, async (req, res) => {
  const { user, session } = getAuth(req);
  const id = parseIdParam(req);

  const revoked = await revokeSession(id, user.id);
  if (!revoked) throw ApiError.notFound('That session no longer exists.');

  if (id === session.id) clearSessionCookie(res);
  await recordActivity({ userId: user.id, type: 'SESSION_REVOKED', targetType: 'session', targetId: id, req });

  res.json({ revoked: true, wasCurrentSession: id === session.id });
});

authRouter.post('/sessions/revoke-others', requireAuth, requireVerifiedEmail, csrfGuard, async (req, res) => {
  const { user, session } = getAuth(req);
  const revoked = await revokeOtherSessions(user.id, session.id);
  await recordActivity({ userId: user.id, type: 'SESSIONS_REVOKED_OTHERS', targetType: 'session', req });
  res.json({ revoked });
});

// ---------------------------------------------------------------------------
// Account-level TOTP two-factor auth. The secret is generated server-side,
// stored AES-256-GCM-wrapped, and only returned once so the user can enrol an
// authenticator. Enabling requires proving the device with a live code.
// ---------------------------------------------------------------------------

authRouter.post('/totp/setup', requireAuth, requireVerifiedEmail, csrfGuard, async (req, res) => {
  const { user } = getAuth(req);
  if (user.totpEnabled) {
    throw ApiError.conflict('Two-factor authentication is already enabled.');
  }

  const secret = generateTotpSecret();
  await prisma.user.update({
    where: { id: user.id },
    data: { totpSecret: wrapTotpSecret(secret.raw), totpEnabled: false },
  });
  secret.raw.fill(0);

  res.json({ secret: secret.base32, otpauthUrl: otpauthUrl(secret.base32, user.email) });
});

authRouter.post(
  '/totp/confirm',
  requireAuth,
  requireVerifiedEmail,
  csrfGuard,
  dbRateLimit({ scope: 'totp-confirm', limit: 10, windowMs: 60 * 60 * 1000, identifier: userIdentifier }),
  async (req, res) => {
  const { user } = getAuth(req);
  const body = parseBody(totpConfirmSchema, req);

  if (!user.totpSecret || user.totpEnabled) {
    throw ApiError.badRequest('Start two-factor setup first.');
  }
  if (!verifyTotp(unwrapTotpSecret(user.totpSecret), body.code)) {
    throw ApiError.badRequest('That code is not correct. Check your authenticator and try again.');
  }

  await prisma.user.update({ where: { id: user.id }, data: { totpEnabled: true } });
  await recordActivity({ userId: user.id, type: 'TOTP_ENABLED', targetType: 'account', req });
  res.json({ enabled: true });
  },
);

authRouter.post(
  '/totp/disable',
  requireAuth,
  requireVerifiedEmail,
  csrfGuard,
  dbRateLimit({ scope: 'totp-disable', limit: 10, windowMs: 60 * 60 * 1000, identifier: userIdentifier }),
  async (req, res) => {
  const { user } = getAuth(req);
  const body = parseBody(totpDisableSchema, req);

  if (!user.totpEnabled || !user.totpSecret) {
    throw ApiError.badRequest('Two-factor authentication is not enabled.');
  }
  if (!verifyTotp(unwrapTotpSecret(user.totpSecret), body.code)) {
    throw ApiError.badRequest('That code is not correct.');
  }

  await prisma.user.update({
    where: { id: user.id },
    data: { totpEnabled: false, totpSecret: null },
  });
  await recordActivity({ userId: user.id, type: 'TOTP_DISABLED', targetType: 'account', req });
  res.json({ enabled: false });
  },
);

async function sendVerificationEmail(
  userId: string,
  email: string,
): Promise<{ required: boolean; delivered: boolean; previewUrl?: string; previewCode?: string }> {
  const token = generateToken(32);
  // A 6-digit code for in-app entry alongside the clickable link. The code's
  // stored hash is scoped with the user id: a 6-digit value is NOT globally
  // unique, and two users issued the same code would collide on the unique
  // tokenHash index at create time.
  const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
  await prisma.$transaction([
    prisma.verificationToken.updateMany({
      where: { userId, type: 'EMAIL_VERIFICATION', usedAt: null },
      data: { usedAt: new Date() },
    }),
    prisma.verificationToken.createMany({
      data: [
        {
          userId,
          type: 'EMAIL_VERIFICATION',
          tokenHash: hashToken(token),
          expiresAt: new Date(Date.now() + EMAIL_VERIFICATION_TTL_MS),
        },
        {
          userId,
          type: 'EMAIL_VERIFICATION',
          tokenHash: hashToken(`${userId}:${code}`),
          expiresAt: new Date(Date.now() + EMAIL_VERIFICATION_TTL_MS),
        },
      ],
    }),
  ]);

  const verifyUrl = `${env.APP_URL}/verify-email?token=${encodeURIComponent(token)}`;
  const { message, actionUrl } = verifyEmailEmail(email, verifyUrl, code);
  const result = await mailer.send(message, actionUrl).catch((error) => {
    logger.warn({ err: error instanceof Error ? error.message : error }, 'verification email failed');
    return { previewUrl: undefined, delivered: false };
  });

  return {
    required: true,
    delivered: result.delivered,
    ...(result.previewUrl && !isProduction ? { previewUrl: result.previewUrl } : {}),
    // Development convenience (console transport sends nothing): lets dev and
    // e2e complete the code flow without reading a mailbox.
    ...(!isProduction ? { previewCode: code } : {}),
  };
}
