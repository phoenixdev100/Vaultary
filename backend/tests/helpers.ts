import { randomBytes, randomUUID } from 'node:crypto';
import request from 'supertest';
import { createApp } from '../src/app.js';
import { prisma } from '../src/db/prisma.js';
import { SESSION_COOKIE, deriveCsrfToken } from '../src/services/session.js';
import { generateToken, hashAuthVerifier, hashToken } from '../src/utils/crypto.js';

export const app = createApp();

/** Matches the KDF bounds the API enforces for every registered account. */
export const TEST_KDF = {
  algorithm: 'argon2id',
  memoryKiB: 19_456,
  iterations: 2,
  parallelism: 1,
} as const;

export function uniqueEmail(tag: string): string {
  return `vaultory-test-${tag}-${randomUUID().slice(0, 8)}@example.com`;
}

/** 32-byte base64url string - the shape the real client derives from a password. */
export function fakeAuthVerifier(): string {
  return randomBytes(32).toString('base64url');
}

/** `v1.<16b64 nonce>.<b64 ciphertext>` - the shape wrapVaultKey produces. */
export function fakeWrappedVaultKey(): string {
  const nonce = randomBytes(12).toString('base64');
  const ciphertext = randomBytes(40).toString('base64');
  return `v1.${nonce}.${ciphertext}`;
}

/** `s1.<b64 ephPub 65B>.<b64 nonce>.<b64 ct>` - structurally valid, undecryptable. */
export function fakeServerWrappedVaultKey(): string {
  const ephPub = Buffer.concat([Buffer.from([4]), randomBytes(64)]).toString('base64');
  const nonce = randomBytes(12).toString('base64');
  const ciphertext = randomBytes(48).toString('base64');
  return `s1.${ephPub}.${nonce}.${ciphertext}`;
}

export function fakeCiphertextPayload(keyVersion = 1) {
  return {
    encVersion: 1 as const,
    keyVersion,
    nonce: randomBytes(12).toString('base64'),
    ciphertext: randomBytes(64).toString('base64'),
  };
}

export interface TestUser {
  id: string;
  email: string;
  agent: ReturnType<typeof request.agent>;
  csrfToken: string;
  /** Dev/test echo of the emailed OTP (console transport sends nothing). */
  previewCode?: string;
}

/**
 * A user + live session created through the service layer, bypassing the
 * rate-limited /signup route. Auth tests keep real signup coverage; seeded
 * users keep the rest of the suite independent of IP rate buckets.
 */
export interface SeededUser {
  id: string;
  email: string;
  cookie: string;
  csrfToken: string;
  /** The plaintext verifier behind authHash - lets tests exercise /login. */
  authVerifier: string;
  /** The seeded user's default (Personal) workspace. */
  workspaceId: string;
}

export async function seedUser(email: string): Promise<SeededUser> {
  const authVerifier = fakeAuthVerifier();
  const user = await prisma.user.create({
    data: {
      email,
      authHash: await hashAuthVerifier(authVerifier),
      kdfAlgorithm: 'argon2id',
      kdfMemoryKiB: 19_456,
      kdfIterations: 2,
      kdfParallelism: 1,
      wrappedVaultKey: fakeWrappedVaultKey(),
      serverWrappedVaultKey: fakeServerWrappedVaultKey(),
      // Seeded users stand in for accounts that already verified - routes
      // behind requireVerifiedEmail must keep working for them.
      emailVerifiedAt: new Date(),
    },
  });

  // Mirrors signup: a default Personal workspace must exist or workspaceScope
  // rejects the seeded user's requests.
  const workspace = await prisma.workspace.create({
    data: { userId: user.id, name: 'Personal', isDefault: true },
  });

  const token = generateToken(32);
  await prisma.session.create({
    data: {
      userId: user.id,
      tokenHash: hashToken(token),
      userAgent: 'vaultory-tests',
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    },
  });

  return {
    id: user.id,
    email,
    cookie: `${SESSION_COOKIE}=${token}`,
    csrfToken: deriveCsrfToken(token),
    authVerifier,
    workspaceId: workspace.id,
  };
}

export async function signupUser(email: string): Promise<TestUser> {
  const agent = request.agent(app);
  const response = await agent.post('/api/auth/signup').send({
    email,
    authVerifier: fakeAuthVerifier(),
    kdf: TEST_KDF,
    wrappedVaultKey: fakeWrappedVaultKey(),
    serverWrappedVaultKey: fakeServerWrappedVaultKey(),
  });

  if (response.status !== 201) {
    throw new Error(`Signup failed for ${email}: ${response.status} ${JSON.stringify(response.body)}`);
  }

  const csrfToken = response.body.csrfToken as string;

  // Signup no longer mails a code automatically - it arrives on an explicit
  // resend, the same button the UI exposes on the verify wall.
  const resend = await agent.post('/api/auth/resend-verification').set('X-CSRF-Token', csrfToken);

  return {
    id: response.body.user.id as string,
    email,
    agent,
    csrfToken,
    previewCode: resend.body.previewCode as string | undefined,
  };
}

/** Marks a signup user verified - the same thing the emailed code does. */
export async function verifyUser(user: TestUser): Promise<void> {
  await prisma.user.update({ where: { id: user.id }, data: { emailVerifiedAt: new Date() } });
}

/** Deletes every user created during a test run; cascades to all owned rows. */
export async function cleanupUsers(emails: string[]): Promise<void> {
  await prisma.user.deleteMany({ where: { email: { in: emails } } });
}
