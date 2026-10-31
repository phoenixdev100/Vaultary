import { createCipheriv, createDecipheriv, createECDH, randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { prisma } from '../src/db/prisma.js';
import { isDisposableEmail } from '../src/services/disposableEmail.js';
import { generateToken, hashToken } from '../src/utils/crypto.js';
import { base32Decode, totpAt } from '../src/utils/totp.js';
import {
  app,
  cleanupUsers,
  fakeAuthVerifier,
  fakeCiphertextPayload,
  fakeServerWrappedVaultKey,
  fakeWrappedVaultKey,
  seedUser,
  signupUser,
  TEST_KDF,
  uniqueEmail,
  verifyUser,
  type SeededUser,
  type TestUser,
} from './helpers.js';

/**
 * Integration tests run against the real dev database with run-scoped users.
 * Cleanup cascades: deleting the user removes sessions, secrets, folders,
 * versions and activity rows created during the run.
 */
const createdEmails: string[] = [];

beforeAll(async () => {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is required for API integration tests');
  }
  // The signup route is bucketed per client IP (10/hour, serverless-safe in
  // Postgres). Reset only the signup scope so the suite is deterministic even
  // after repeated local runs - other scopes and users are untouched.
  await prisma.rateLimitCounter.deleteMany({ where: { key: { startsWith: 'signup:' } } });
});

afterAll(async () => {
  await cleanupUsers(createdEmails);
  await prisma.$disconnect();
});

function track<T extends { email: string }>(user: T): T {
  createdEmails.push(user.email);
  return user;
}

async function makeUser(tag: string): Promise<TestUser> {
  return track(await signupUser(uniqueEmail(tag)));
}

async function makeSeededUser(tag: string): Promise<SeededUser> {
  return track(await seedUser(uniqueEmail(tag)));
}

/** Every request in an authed call carries the session cookie + CSRF header. */
function authed(user: SeededUser) {
  const agent = request.agent(app);
  agent.set('Cookie', user.cookie).set('X-CSRF-Token', user.csrfToken);
  return agent;
}

describe('health and hardening', () => {
  it('answers /api/health with database status', async () => {
    const response = await request(app).get('/api/health');
    expect(response.status).toBe(200);
    expect(response.body.service).toBe('vaultory-api');
    expect(response.body.database).toBe('up');
  });

  it('sets hardened response headers', async () => {
    const response = await request(app).get('/api/health');
    expect(response.headers['cache-control']).toContain('no-store');
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-powered-by']).toBeUndefined();
  });

  it('rejects unsafe requests from an origin that is not allowed', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .set('Origin', 'https://evil.example.com')
      .send({ email: 'a@b.c', authVerifier: fakeAuthVerifier() });
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('origin_not_allowed');
  });
});

describe('authentication', () => {
  it('signs up, issues a session cookie and CSRF token', async () => {
    const user = await makeUser('signup');
    await verifyUser(user);

    const me = await user.agent.get('/api/auth/me');
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe(user.email);
    expect(me.body.csrfToken).toBe(user.csrfToken);
    expect(me.body.session.current).toBe(true);

    // Starter folders are provisioned at signup.
    const folders = await user.agent.get('/api/folders');
    expect(folders.status).toBe(200);
    expect(folders.body.items.length).toBeGreaterThanOrEqual(2);
  });

  it('gates vault routes until the email is verified, then unlocks via the OTP code', async () => {
    const user = await makeUser('unverified');

    // Unverified: vault + security reads are rejected with the dedicated code.
    const blocked = await user.agent.get('/api/secrets');
    expect(blocked.status).toBe(403);
    expect(blocked.body.error.code).toBe('email_not_verified');

    // Sessions, TOTP enrolment, passkeys and the favicon proxy sit behind
    // the same gate - only verification, logout and account settings stay open.
    for (const path of ['/api/auth/sessions', '/api/account/passkeys', '/api/meta/favicon?domain=example.com']) {
      const gated = await user.agent.get(path);
      expect(gated.status).toBe(403);
      expect(gated.body.error.code).toBe('email_not_verified');
    }
    const totpSetup = await user.agent.post('/api/auth/totp/setup').set('X-CSRF-Token', user.csrfToken);
    expect(totpSetup.status).toBe(403);

    // The OTP was requested explicitly (resend); typing it verifies the account.
    expect(user.previewCode).toMatch(/^\d{6}$/);
    const badCode = await user.agent
      .post('/api/auth/verify-email-code')
      .set('X-CSRF-Token', user.csrfToken)
      .send({ code: '000000' });
    // A wrong code is a clean 400, not a verification.
    if (badCode.status === 200) {
      // Astronomically unlikely: the random code really was 000000.
      expect(user.previewCode).toBe('000000');
    } else {
      expect(badCode.status).toBe(400);
    }

    const verify = await user.agent
      .post('/api/auth/verify-email-code')
      .set('X-CSRF-Token', user.csrfToken)
      .send({ code: user.previewCode });
    expect(verify.status).toBe(200);
    expect(verify.body.verified).toBe(true);

    // The session resolves the fresh user row, so the gate opens immediately.
    const folders = await user.agent.get('/api/folders');
    expect(folders.status).toBe(200);
  });

  it('mails no verification code at signup - only on explicit request', async () => {
    const email = uniqueEmail('no-auto-otp');
    createdEmails.push(email);
    const agent = request.agent(app);
    const signup = await agent.post('/api/auth/signup').send({
      email,
      authVerifier: fakeAuthVerifier(),
      kdf: TEST_KDF,
      wrappedVaultKey: fakeWrappedVaultKey(),
      serverWrappedVaultKey: fakeServerWrappedVaultKey(),
    });
    expect(signup.status).toBe(201);
    // The response no longer advertises an auto-sent OTP.
    expect(signup.body.emailVerification).toBeUndefined();

    // And no token row exists until the user asks for one.
    const userId = signup.body.user.id as string;
    const before = await prisma.verificationToken.count({
      where: { userId, type: 'EMAIL_VERIFICATION' },
    });
    expect(before).toBe(0);

    const resend = await agent
      .post('/api/auth/resend-verification')
      .set('X-CSRF-Token', signup.body.csrfToken);
    expect(resend.status).toBe(202);
    expect(resend.body.previewCode).toMatch(/^\d{6}$/);
    const after = await prisma.verificationToken.count({
      where: { userId, type: 'EMAIL_VERIFICATION' },
    });
    expect(after).toBeGreaterThan(0);
  });

  it('resends a verification code for an unverified account', async () => {
    const user = await makeUser('resend');

    const resend = await user.agent
      .post('/api/auth/resend-verification')
      .set('X-CSRF-Token', user.csrfToken);
    expect(resend.status).toBe(202);
    expect(resend.body.required).toBe(true);
    // Dev/test transport echoes the code so the flow is exercisable.
    expect(resend.body.previewCode).toMatch(/^\d{6}$/);

    // Already-verified users get a no-op answer.
    await verifyUser(user);
    const again = await user.agent
      .post('/api/auth/resend-verification')
      .set('X-CSRF-Token', user.csrfToken);
    expect(again.status).toBe(200);
    expect(again.body.required).toBe(false);
  });

  it('rejects login with a wrong verifier', async () => {
    // Seeded: the login route is what is under test, not signup.
    const user = await makeSeededUser('login');

    const response = await request(app)
      .post('/api/auth/login')
      .send({ email: user.email, authVerifier: fakeAuthVerifier() });

    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('unauthorized');
    // Generic message - never reveals whether the email exists.
    expect(response.body.error.message).toBe('Invalid email or password.');
  });

  it('rejects duplicate signup with 409', async () => {
    const user = await makeSeededUser('dup');

    const response = await request(app).post('/api/auth/signup').send({
      email: user.email,
      authVerifier: fakeAuthVerifier(),
      kdf: TEST_KDF,
      wrappedVaultKey: fakeWrappedVaultKey(),
    });
    expect(response.status).toBe(409);
  });

  it('requires a session for authenticated routes', async () => {
    const response = await request(app).get('/api/secrets');
    expect(response.status).toBe(401);
  });

  it('logs out and invalidates the session', async () => {
    const user = await makeSeededUser('logout');

    const logout = await authed(user).post('/api/auth/logout');
    expect(logout.status).toBe(204);

    const me = await authed(user).get('/api/auth/me');
    expect(me.status).toBe(401);
  });
});

describe('email flows', () => {
  it('forgot-password answers identically for known and unknown emails', async () => {
    const user = await makeSeededUser('fp-known');

    const known = await request(app).post('/api/auth/forgot-password').send({ email: user.email });
    expect(known.status).toBe(202);
    expect(known.body.message).toMatch(/if an account exists/i);

    const unknown = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: uniqueEmail('fp-unknown') });
    expect(unknown.status).toBe(202);
    // Same generic message - no account enumeration.
    expect(unknown.body.message).toBe(known.body.message);

    const malformed = await request(app).post('/api/auth/forgot-password').send({ email: 'not-an-email' });
    expect(malformed.status).toBe(400);
  });

  it('issues reset links that expire after exactly 10 minutes', async () => {
    const user = await makeSeededUser('fp-ttl');

    const res = await request(app).post('/api/auth/forgot-password').send({ email: user.email });
    expect(res.status).toBe(202);

    const record = await prisma.verificationToken.findFirst({
      where: { userId: user.id, type: 'PASSWORD_RESET', usedAt: null },
      orderBy: { createdAt: 'desc' },
    });
    expect(record).not.toBeNull();
    // createdAt (DB clock) and expiresAt (app clock) are same-machine, so the
    // delta is the configured TTL: exactly 10 minutes.
    const ttlMs = record!.expiresAt.getTime() - record!.createdAt.getTime();
    expect(Math.abs(ttlMs - 10 * 60 * 1000)).toBeLessThan(5000);
  });

  it('rejects expired and already-used reset tokens', async () => {
    const user = await makeSeededUser('fp-dead');

    const expiredToken = generateToken(32);
    await prisma.verificationToken.create({
      data: {
        userId: user.id,
        type: 'PASSWORD_RESET',
        tokenHash: hashToken(expiredToken),
        // Expired one second ago.
        expiresAt: new Date(Date.now() - 1000),
      },
    });

    const expired = await request(app).post('/api/auth/reset-token-info').send({ token: expiredToken });
    expect(expired.status).toBe(400);
    expect(expired.body.error.code).toBe('invalid_token');

    const usedToken = generateToken(32);
    await prisma.verificationToken.create({
      data: {
        userId: user.id,
        type: 'PASSWORD_RESET',
        tokenHash: hashToken(usedToken),
        usedAt: new Date(),
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      },
    });

    const used = await request(app).post('/api/auth/reset-token-info').send({ token: usedToken });
    expect(used.status).toBe(400);
    expect(used.body.error.code).toBe('invalid_token');

    const missing = await request(app).post('/api/auth/reset-token-info').send({ token: generateToken(32) });
    expect(missing.status).toBe(400);
    expect(missing.body.error.code).toBe('invalid_token');
  });

  it('burns a completed reset token so the link cannot be replayed', async () => {
    const user = await makeSeededUser('fp-replay');
    const token = await (async () => {
      const t = generateToken(32);
      await prisma.verificationToken.create({
        data: {
          userId: user.id,
          type: 'PASSWORD_RESET',
          tokenHash: hashToken(t),
          expiresAt: new Date(Date.now() + 10 * 60 * 1000),
        },
      });
      return t;
    })();

    const done = await request(app).post('/api/auth/reset-password').send({
      token,
      authVerifier: fakeAuthVerifier(),
      kdf: TEST_KDF,
      wrappedVaultKey: fakeWrappedVaultKey(),
      serverWrappedVaultKey: fakeServerWrappedVaultKey(),
      vaultKeyPreserved: true,
    });
    expect(done.status).toBe(200);

    // Same token a second time: consumed, so invalid.
    const replay = await request(app).post('/api/auth/reset-token-info').send({ token });
    expect(replay.status).toBe(400);
    expect(replay.body.error.code).toBe('invalid_token');
  });

  it('resend invalidates the previous verification code', async () => {
    // Seeded + manually-unverified: resend needs an authed unverified session.
    const user = await makeSeededUser('reissue');
    await prisma.user.update({ where: { id: user.id }, data: { emailVerifiedAt: null } });
    const firstCode = '111111';
    await prisma.verificationToken.create({
      data: {
        userId: user.id,
        type: 'EMAIL_VERIFICATION',
        tokenHash: hashToken(firstCode),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      },
    });

    const resend = await authed(user).post('/api/auth/resend-verification');
    expect(resend.status).toBe(202);
    const secondCode = resend.body.previewCode as string;
    expect(secondCode).toMatch(/^\d{6}$/);

    // The first code was consumed-at-issuance - it must no longer verify.
    const old = await authed(user).post('/api/auth/verify-email-code').send({ code: firstCode });
    expect(old.status).toBe(400);

    const fresh = await authed(user).post('/api/auth/verify-email-code').send({ code: secondCode });
    expect(fresh.status).toBe(200);
    expect(fresh.body.verified).toBe(true);
  });

  it('flags every common disposable domain shape', () => {
    // Pure unit coverage - keeps the 10/h signup bucket for real signups.
    for (const email of [
      'user@mailinator.com',
      'user@10minutemail.com',
      'user@guerrillamail.com',
      'user@yopmail.com',
      'user@a.b.c.yopmail.com', // subdomain of a listed domain
      'USER@MAILINATOR.COM', // case-insensitive
    ]) {
      expect(isDisposableEmail(email)).toBe(true);
    }
    for (const email of ['a@example.com', 'someone@gmail.com', 'me@outlook.co.in']) {
      expect(isDisposableEmail(email)).toBe(false);
    }
  });

  it('rejects disposable email domains on signup, prelogin, login and forgot-password', async () => {
    const email = 'user@mailinator.com';

    const prelogin = await request(app).post('/api/auth/prelogin').send({ email });
    expect(prelogin.status).toBe(400);
    expect(prelogin.body.error.code).toBe('disposable_email');

    const signup = await request(app).post('/api/auth/signup').send({
      email,
      authVerifier: fakeAuthVerifier(),
      kdf: TEST_KDF,
      wrappedVaultKey: fakeWrappedVaultKey(),
    });
    expect(signup.status).toBe(400);
    expect(signup.body.error.code).toBe('disposable_email');

    const login = await request(app)
      .post('/api/auth/login')
      .send({ email, authVerifier: fakeAuthVerifier() });
    expect(login.status).toBe(400);
    expect(login.body.error.code).toBe('disposable_email');

    const forgot = await request(app).post('/api/auth/forgot-password').send({ email });
    expect(forgot.status).toBe(400);
    expect(forgot.body.error.code).toBe('disposable_email');
  });

  it('silently rejects signups that fill the honeypot field', async () => {
    const email = uniqueEmail('honeypot');
    const res = await request(app)
      .post('/api/auth/signup')
      .send({
        email,
        authVerifier: fakeAuthVerifier(),
        kdf: TEST_KDF,
        wrappedVaultKey: fakeWrappedVaultKey(),
        website: 'http://spam.example.com', // a human never fills this
      });
    expect(res.status).toBe(400);
    // And nothing was created.
    const created = await prisma.user.findUnique({ where: { email } });
    expect(created).toBeNull();
  });

  it('rejects malformed and short codes before hitting the token store', async () => {
    // Seeded instead of a real signup - keeps the suite inside the 10/h signup bucket.
    const user = await makeSeededUser('bad-code');
    await prisma.user.update({ where: { id: user.id }, data: { emailVerifiedAt: null } });

    for (const code of ['12345', '1234567', 'abcdef', '']) {
      const res = await authed(user).post('/api/auth/verify-email-code').send({ code });
      expect(res.status).toBe(400);
    }
  });
});

/**
 * Password reset with vault-key escrow. The browser-side ECDH dance is
 * simulated with node:crypto, which shares the same wire format as WebCrypto:
 * the raw P-256 shared secret is used directly as the AES-256-GCM key.
 */
describe('password reset escrow', () => {
  const ESCROW_AAD = Buffer.from('vaultory|escrow|v1', 'utf8');

  /** Client-side escrow, exactly what escrowVaultKeyForServer produces. */
  function escrowToServer(vaultKeyRaw: Buffer, serverPubRaw: Buffer): string {
    const eph = createECDH('prime256v1');
    eph.generateKeys();
    const shared = eph.computeSecret(serverPubRaw);
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', shared, nonce);
    cipher.setAAD(ESCROW_AAD);
    const ct = Buffer.concat([cipher.update(vaultKeyRaw), cipher.final(), cipher.getAuthTag()]);
    return `s1.${eph.getPublicKey().toString('base64')}.${nonce.toString('base64')}.${ct.toString('base64')}`;
  }

  /** Client-side unwrap of the blob returned by /auth/reset-prepare. */
  function openResetBlob(blob: string, clientEph: ReturnType<typeof createECDH>, serverPubRaw: Buffer): Buffer {
    const parts = blob.split('.');
    expect(parts[0]).toBe('s1');
    const shared = clientEph.computeSecret(serverPubRaw);
    const ct = Buffer.from(parts[2] ?? '', 'base64');
    const decipher = createDecipheriv('aes-256-gcm', shared, Buffer.from(parts[1] ?? '', 'base64'));
    decipher.setAAD(ESCROW_AAD);
    decipher.setAuthTag(ct.subarray(-16));
    return Buffer.concat([decipher.update(ct.subarray(0, -16)), decipher.final()]);
  }

  async function makeResetToken(userId: string): Promise<string> {
    const token = generateToken(32);
    await prisma.verificationToken.create({
      data: {
        userId,
        type: 'PASSWORD_RESET',
        tokenHash: hashToken(token),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      },
    });
    return token;
  }

  it('exposes the server escrow public key', async () => {
    const response = await request(app).get('/api/auth/server-key');
    expect(response.status).toBe(200);
    // Raw uncompressed P-256 point: 65 bytes -> 88 base64 chars.
    expect(Buffer.from(response.body.publicKey, 'base64').length).toBe(65);
  });

  it('recovers the same vault key through a verified reset', async () => {
    const user = await makeSeededUser('reset-keep');
    const keyRes = await request(app).get('/api/auth/server-key');
    const serverPubRaw = Buffer.from(keyRes.body.publicKey as string, 'base64');

    // Give the account a real escrow blob for a known 32-byte vault key.
    const vaultKeyRaw = randomBytes(32);
    await prisma.user.update({
      where: { id: user.id },
      data: { serverWrappedVaultKey: escrowToServer(vaultKeyRaw, serverPubRaw) },
    });
    // A secret encrypted under vault key version 1.
    await prisma.secret.create({
      data: { userId: user.id, workspaceId: user.workspaceId, title: 'Keeps working', category: 'LOGIN', ...fakeCiphertextPayload() },
    });

    const token = await makeResetToken(user.id);

    const info = await request(app).post('/api/auth/reset-token-info').send({ token });
    expect(info.body.vaultRecoverable).toBe(true);

    // reset-prepare: server unwraps the escrow and re-encrypts to our key.
    const clientEph = createECDH('prime256v1');
    clientEph.generateKeys();
    const prep = await request(app)
      .post('/api/auth/reset-prepare')
      .send({ token, clientPublicKey: clientEph.getPublicKey().toString('base64') });
    expect(prep.status).toBe(200);
    expect(prep.body.recoverable).toBe(true);
    // The exact vault key bytes survived the escrow round trip.
    expect(openResetBlob(prep.body.blob, clientEph, serverPubRaw).equals(vaultKeyRaw)).toBe(true);

    const done = await request(app).post('/api/auth/reset-password').send({
      token,
      authVerifier: fakeAuthVerifier(),
      kdf: TEST_KDF,
      wrappedVaultKey: fakeWrappedVaultKey(),
      serverWrappedVaultKey: escrowToServer(vaultKeyRaw, serverPubRaw),
      vaultKeyPreserved: true,
    });
    expect(done.status).toBe(200);
    expect(done.body.vaultKeyPreserved).toBe(true);
    expect(done.body.vaultKeyVersion).toBe(1); // unchanged - no rotation
    expect(done.body.strandedSecrets).toBe(0);

    const secret = await prisma.secret.findFirst({ where: { userId: user.id } });
    expect(secret?.keyVersion).toBe(1);
  });

  it('rotates the key for accounts without an escrow blob', async () => {
    const user = await makeSeededUser('reset-legacy');
    await prisma.user.update({ where: { id: user.id }, data: { serverWrappedVaultKey: null } });
    await prisma.secret.create({
      data: { userId: user.id, workspaceId: user.workspaceId, title: 'Legacy item', category: 'LOGIN', ...fakeCiphertextPayload() },
    });

    const token = await makeResetToken(user.id);

    const info = await request(app).post('/api/auth/reset-token-info').send({ token });
    expect(info.body.vaultRecoverable).toBe(false);

    const clientEph = createECDH('prime256v1');
    clientEph.generateKeys();
    const prep = await request(app)
      .post('/api/auth/reset-prepare')
      .send({ token, clientPublicKey: clientEph.getPublicKey().toString('base64') });
    expect(prep.body.recoverable).toBe(false);

    // The destructive path still demands the acknowledgement.
    const refused = await request(app).post('/api/auth/reset-password').send({
      token,
      authVerifier: fakeAuthVerifier(),
      kdf: TEST_KDF,
      wrappedVaultKey: fakeWrappedVaultKey(),
      vaultKeyPreserved: false,
    });
    expect(refused.status).toBe(400);

    const done = await request(app).post('/api/auth/reset-password').send({
      token,
      authVerifier: fakeAuthVerifier(),
      kdf: TEST_KDF,
      wrappedVaultKey: fakeWrappedVaultKey(),
      vaultKeyPreserved: false,
      acknowledgeVaultLoss: true,
    });
    expect(done.status).toBe(200);
    expect(done.body.vaultKeyPreserved).toBe(false);
    expect(done.body.vaultKeyVersion).toBe(2); // rotated
    expect(done.body.strandedSecrets).toBe(1);
  });
});

describe('CSRF protection', () => {
  it('rejects state-changing requests without the CSRF header', async () => {
    const user = await makeSeededUser('csrf');

    const response = await request(app)
      .post('/api/secrets')
      .set('Cookie', user.cookie)
      .send({ title: 'No token', category: 'CUSTOM', ...fakeCiphertextPayload() });

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('csrf_failed');
  });

  it('rejects requests with a wrong CSRF token', async () => {
    const user = await makeSeededUser('csrfbad');

    const response = await request(app)
      .post('/api/secrets')
      .set('Cookie', user.cookie)
      .set('X-CSRF-Token', 'not-the-token')
      .send({ title: 'Bad token', category: 'CUSTOM', ...fakeCiphertextPayload() });

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('csrf_failed');
  });
});

describe('secrets and authorization', () => {
  it('performs CRUD scoped to the owning user', async () => {
    const alice = await makeSeededUser('alice');
    const payload = fakeCiphertextPayload();

    const created = await authed(alice)
      .post('/api/secrets')
      .send({ title: 'GitHub PAT', category: 'API_KEY', tags: ['dev'], ...payload });
    expect(created.status).toBe(201);

    const secretId = created.body.secret.id as string;
    expect(created.body.secret.ciphertext).toBe(payload.ciphertext);
    expect(created.body.secret.version).toBe(1);

    const listed = await authed(alice).get('/api/secrets');
    expect(listed.body.items.some((item: { id: string }) => item.id === secretId)).toBe(true);

    const updated = await authed(alice)
      .patch(`/api/secrets/${secretId}`)
      .send({ title: 'GitHub PAT (rotated)', isFavorite: true });
    expect(updated.status).toBe(200);
    expect(updated.body.secret.title).toBe('GitHub PAT (rotated)');
    expect(updated.body.secret.isFavorite).toBe(true);

    const deleted = await authed(alice).delete(`/api/secrets/${secretId}`);
    expect(deleted.status).toBe(204);
  });

  it('snapshots a previous encrypted version on payload updates and restores it', async () => {
    const user = await makeSeededUser('versions');
    const first = fakeCiphertextPayload();
    const second = fakeCiphertextPayload();

    const created = await authed(user)
      .post('/api/secrets')
      .send({ title: 'Versioned item', category: 'LOGIN', ...first });
    const secretId = created.body.secret.id as string;

    const updated = await authed(user)
      .patch(`/api/secrets/${secretId}`)
      .send({ title: 'Versioned item v2', ...second });
    expect(updated.status).toBe(200);
    expect(updated.body.secret.version).toBe(2);
    expect(updated.body.secret.ciphertext).toBe(second.ciphertext);

    const versions = await authed(user).get(`/api/secrets/${secretId}/versions`);
    expect(versions.status).toBe(200);
    expect(versions.body.items).toHaveLength(1);
    expect(versions.body.items[0].version).toBe(1);
    // The snapshot is the *encrypted* previous payload - no plaintext anywhere.
    expect(versions.body.items[0].ciphertext).toBe(first.ciphertext);

    const restored = await authed(user).post(
      `/api/secrets/${secretId}/versions/${versions.body.items[0].id}/restore`,
    );
    expect(restored.status).toBe(200);
    expect(restored.body.secret.ciphertext).toBe(first.ciphertext);
    expect(restored.body.secret.title).toBe('Versioned item');
  });

  it('denies every cross-user access path', async () => {
    const alice = await makeSeededUser('owner');
    const bob = await makeSeededUser('intruder');

    const created = await authed(alice)
      .post('/api/secrets')
      .send({ title: 'Alice-only secret', category: 'SECURE_NOTE', ...fakeCiphertextPayload() });
    const secretId = created.body.secret.id as string;

    // Bob cannot read, update, delete or version-list Alice's secret.
    expect((await authed(bob).get(`/api/secrets/${secretId}`)).status).toBe(404);
    expect((await authed(bob).patch(`/api/secrets/${secretId}`).send({ title: 'stolen' })).status).toBe(404);
    expect((await authed(bob).delete(`/api/secrets/${secretId}`)).status).toBe(404);
    expect((await authed(bob).get(`/api/secrets/${secretId}/versions`)).status).toBe(404);

    // Bob's listing never contains it.
    const bobList = await authed(bob).get('/api/secrets');
    expect(bobList.body.items.some((item: { id: string }) => item.id === secretId)).toBe(false);

    // Bob cannot place items into Alice's folder either.
    const aliceFolder = await authed(alice).post('/api/folders').send({ name: 'Alice folder' });
    const moveAttempt = await authed(bob)
      .post('/api/secrets')
      .send({
        title: 'Sneaky',
        category: 'CUSTOM',
        folderId: aliceFolder.body.folder.id,
        ...fakeCiphertextPayload(),
      });
    expect(moveAttempt.status).toBe(400);
  });

  it('never stores or returns plaintext fields for secret values', async () => {
    const user = await makeSeededUser('plaintext');
    const marker = 'hunter2-plaintext-marker';
    const payload = fakeCiphertextPayload();

    const created = await authed(user)
      .post('/api/secrets')
      .send({ title: 'Marker item', category: 'LOGIN', ...payload });
    const secretId = created.body.secret.id as string;

    // The API surface exposes only ciphertext + metadata.
    const dto = created.body.secret;
    expect(dto).not.toHaveProperty('password');
    expect(dto).not.toHaveProperty('value');
    expect(dto.ciphertext).toBe(payload.ciphertext);

    // The database row itself holds only the encrypted blob.
    const row = await prisma.secret.findUnique({ where: { id: secretId } });
    expect(row).not.toBeNull();
    expect(row!.ciphertext).toBe(payload.ciphertext);
    expect(row!.ciphertext).not.toContain(marker);
    expect(JSON.stringify(row)).not.toContain(marker);
  });
});

describe('attachments', () => {
  function fakeAttachment(overrides: Record<string, unknown> = {}) {
    return {
      fileName: 'prod.env',
      mimeType: 'text/plain',
      size: 128,
      keyVersion: 1,
      nonce: randomBytes(12).toString('base64'),
      ciphertext: randomBytes(256).toString('base64'),
      ...overrides,
    };
  }

  async function ownedSecret(user: SeededUser) {
    const created = await authed(user)
      .post('/api/secrets')
      .send({ title: 'Env file holder', category: 'ENV_VARS', ...fakeCiphertextPayload() });
    expect(created.status).toBe(201);
    return created.body.secret.id as string;
  }

  it('uploads, lists, downloads and deletes an encrypted file', async () => {
    const user = await makeSeededUser('attachments');
    const secretId = await ownedSecret(user);
    const blob = fakeAttachment();

    const uploaded = await authed(user).post(`/api/secrets/${secretId}/attachments`).send(blob);
    expect(uploaded.status).toBe(201);
    const attachmentId = uploaded.body.attachment.id as string;
    // List/download responses expose metadata; ciphertext stays server-side until fetched.
    expect(uploaded.body.attachment).not.toHaveProperty('ciphertext');
    expect(uploaded.body.attachment.fileName).toBe('prod.env');
    expect(uploaded.body.attachment.size).toBe(128);

    const listed = await authed(user).get(`/api/secrets/${secretId}/attachments`);
    expect(listed.status).toBe(200);
    expect(listed.body.items).toHaveLength(1);
    expect(listed.body.items[0].id).toBe(attachmentId);
    expect(listed.body.items[0]).not.toHaveProperty('ciphertext');

    const downloaded = await authed(user).get(`/api/secrets/${secretId}/attachments/${attachmentId}`);
    expect(downloaded.status).toBe(200);
    expect(downloaded.body.attachment.ciphertext).toBe(blob.ciphertext);
    expect(downloaded.body.attachment.nonce).toBe(blob.nonce);

    const deleted = await authed(user).delete(`/api/secrets/${secretId}/attachments/${attachmentId}`);
    expect(deleted.status).toBe(204);
    expect((await authed(user).get(`/api/secrets/${secretId}/attachments/${attachmentId}`)).status).toBe(404);
  });

  it('denies other users every attachment path', async () => {
    const alice = await makeSeededUser('att-owner');
    const bob = await makeSeededUser('att-intruder');
    const secretId = await ownedSecret(alice);

    const uploaded = await authed(alice).post(`/api/secrets/${secretId}/attachments`).send(fakeAttachment());
    const attachmentId = uploaded.body.attachment.id as string;

    expect((await authed(bob).get(`/api/secrets/${secretId}/attachments`)).status).toBe(404);
    expect((await authed(bob).post(`/api/secrets/${secretId}/attachments`).send(fakeAttachment())).status).toBe(404);
    expect((await authed(bob).get(`/api/secrets/${secretId}/attachments/${attachmentId}`)).status).toBe(404);
    expect((await authed(bob).delete(`/api/secrets/${secretId}/attachments/${attachmentId}`)).status).toBe(404);
  });

  it('rejects oversized files, unsafe names and non-base64 blobs', async () => {
    const user = await makeSeededUser('att-validation');
    const secretId = await ownedSecret(user);

    const tooBig = await authed(user)
      .post(`/api/secrets/${secretId}/attachments`)
      .send(fakeAttachment({ size: 6 * 1024 * 1024 }));
    expect(tooBig.status).toBe(400);

    const pathName = await authed(user)
      .post(`/api/secrets/${secretId}/attachments`)
      .send(fakeAttachment({ fileName: '../../etc/passwd' }));
    expect(pathName.status).toBe(400);

    const notBase64 = await authed(user)
      .post(`/api/secrets/${secretId}/attachments`)
      .send(fakeAttachment({ ciphertext: 'not!!base64!!' }));
    expect(notBase64.status).toBe(400);
  });

  it('accepts every new secret category', async () => {
    const user = await makeSeededUser('categories');
    const categories = [
      'CLOUD',
      'ENV_VARS',
      'PRIVATE_KEY',
      'PAYMENT',
      'EMAIL_SERVICE',
      'IDENTITY',
      'MOBILE',
      'CRYPTO',
      'PERSONAL',
    ];

    for (const category of categories) {
      const created = await authed(user)
        .post('/api/secrets')
        .send({ title: `Test ${category}`, category, ...fakeCiphertextPayload() });
      expect(created.status).toBe(201);
      expect(created.body.secret.category).toBe(category);
    }
  });

  it('keeps attachments while trashed and deletes them on permanent delete', async () => {
    const user = await makeSeededUser('att-cascade');
    const secretId = await ownedSecret(user);
    await authed(user).post(`/api/secrets/${secretId}/attachments`).send(fakeAttachment());

    // Trash preserves the attachment so restore brings the file back.
    expect((await authed(user).delete(`/api/secrets/${secretId}`)).status).toBe(204);
    expect(await prisma.attachment.count({ where: { secretId } })).toBe(1);

    // Permanent delete cascades.
    expect((await authed(user).delete(`/api/secrets/${secretId}/permanent`)).status).toBe(204);
    expect(await prisma.attachment.count({ where: { secretId } })).toBe(0);
  });
});

describe('folders', () => {
  it('creates, renames and deletes folders with an explicit strategy', async () => {
    const user = await makeSeededUser('folders');

    const folder = await authed(user).post('/api/folders').send({ name: 'Servers' });
    expect(folder.status).toBe(201);
    const folderId = folder.body.folder.id as string;

    const secret = await authed(user)
      .post('/api/secrets')
      .send({ title: 'SSH root', category: 'SERVER_SSH', folderId, ...fakeCiphertextPayload() });
    const secretId = secret.body.secret.id as string;

    const renamed = await authed(user).patch(`/api/folders/${folderId}`).send({ name: 'Production servers' });
    expect(renamed.status).toBe(200);
    expect(renamed.body.folder.name).toBe('Production servers');

    // detach keeps the secret, unfiled.
    const deleted = await authed(user).delete(`/api/folders/${folderId}?strategy=detach`);
    expect(deleted.status).toBe(200);
    expect(deleted.body.detachedSecrets).toBe(1);

    const after = await authed(user).get(`/api/secrets/${secretId}`);
    expect(after.status).toBe(200);
    expect(after.body.secret.folderId).toBeNull();
  });

  it('nests folders up to the depth cap, blocks cycles, and lifts children on delete', async () => {
    const user = await makeSeededUser('nested-folders');
    const agent = authed(user);

    // root -> child -> grandchild (depth cap is 3)
    const root = await agent.post('/api/folders').send({ name: 'Work' });
    expect(root.status).toBe(201);
    const child = await agent.post('/api/folders').send({ name: 'Clients', parentId: root.body.folder.id });
    expect(child.status).toBe(201);
    expect(child.body.folder.parentId).toBe(root.body.folder.id);
    const grandchild = await agent
      .post('/api/folders')
      .send({ name: 'Acme', parentId: child.body.folder.id });
    expect(grandchild.status).toBe(201);

    // Level 4 exceeds the cap.
    const tooDeep = await agent
      .post('/api/folders')
      .send({ name: 'Too deep', parentId: grandchild.body.folder.id });
    expect(tooDeep.status).toBe(400);

    // A folder cannot move under itself or its own descendant.
    const ontoSelf = await agent.patch(`/api/folders/${root.body.folder.id}`).send({ parentId: root.body.folder.id });
    expect(ontoSelf.status).toBe(400);
    const ontoDescendant = await agent
      .patch(`/api/folders/${root.body.folder.id}`)
      .send({ parentId: grandchild.body.folder.id });
    expect(ontoDescendant.status).toBe(400);

    // A foreign folder cannot be used as a parent.
    const stranger = await makeSeededUser('nested-stranger');
    const foreign = await authed(stranger).post('/api/folders').send({ name: 'Not yours' });
    const crossUser = await agent
      .post('/api/folders')
      .send({ name: 'Nope', parentId: foreign.body.folder.id });
    expect(crossUser.status).toBe(404);

    // Deleting the child lifts the grandchild to the root - never deletes it.
    const gone = await agent.delete(`/api/folders/${child.body.folder.id}`);
    expect(gone.status).toBe(200);
    expect(gone.body.detachedFolders).toBe(1);
    const list = await agent.get('/api/folders');
    const lifted = list.body.items.find((f: { id: string }) => f.id === grandchild.body.folder.id);
    expect(lifted).toBeTruthy();
    expect(lifted.parentId).toBe(root.body.folder.id);
  });
});

describe('account TOTP two-factor', () => {
  it('enrols via setup+confirm, then requires the code to log in, and disables again', async () => {
    const user = await makeSeededUser('totp');

    // Setup returns the enrolment secret + otpauth URI exactly once.
    const setup = await authed(user).post('/api/auth/totp/setup');
    expect(setup.status).toBe(200);
    expect(setup.body.otpauthUrl).toContain('otpauth://totp/');
    const secret = base32Decode(setup.body.secret as string);

    // The raw secret must not live in the database.
    const row = await prisma.user.findUnique({ where: { id: user.id } });
    expect(row!.totpSecret).not.toContain(setup.body.secret);
    expect(row!.totpEnabled).toBe(false);

    // A wrong code cannot confirm enrolment.
    const bad = await authed(user).post('/api/auth/totp/confirm').send({ code: '000000' });
    expect(bad.status).toBe(400);

    const good = await authed(user)
      .post('/api/auth/totp/confirm')
      .send({ code: totpAt(secret, Date.now()) });
    expect(good.status).toBe(200);

    const me = await authed(user).get('/api/auth/me');
    expect(me.body.user.totpEnabled).toBe(true);

    // Password-only login now stops at the MFA step: no session cookie.
    const login = await request(app)
      .post('/api/auth/login')
      .send({ email: user.email, authVerifier: user.authVerifier });
    expect(login.status).toBe(200);
    expect(login.body.mfaRequired).toBe(true);
    expect(login.headers['set-cookie']).toBeUndefined();
    const mfaToken = login.body.mfaToken as string;

    // Wrong code + forged token are both rejected.
    const wrong = await request(app)
      .post('/api/auth/login/mfa')
      .send({ mfaToken, code: '999999' });
    expect(wrong.status).toBe(401);
    const forged = await request(app)
      .post('/api/auth/login/mfa')
      .send({ mfaToken: `${mfaToken}x`, code: totpAt(secret, Date.now()) });
    expect(forged.status).toBe(401);

    // Correct code completes login and issues the session.
    const complete = await request(app)
      .post('/api/auth/login/mfa')
      .send({ mfaToken, code: totpAt(secret, Date.now()) });
    expect(complete.status).toBe(200);
    expect(complete.body.user.email).toBe(user.email);
    const setCookie = complete.headers['set-cookie'];
    expect(Array.isArray(setCookie) ? setCookie.join(';') : String(setCookie)).toContain('vaultory_session=');

    // Disable requires a live code too.
    const disabled = await authed(user)
      .post('/api/auth/totp/disable')
      .send({ code: totpAt(secret, Date.now()) });
    expect(disabled.status).toBe(200);

    const cleared = await prisma.user.findUnique({ where: { id: user.id } });
    expect(cleared!.totpEnabled).toBe(false);
    expect(cleared!.totpSecret).toBeNull();
  });
});

describe('browser extension pairing', () => {
  it('mints a single-use link code that exchanges for a Bearer session', async () => {
    const user = await makeSeededUser('ext');

    // Anonymous callers cannot mint a pairing code.
    const anon = await request(app).post('/api/auth/extension-link');
    expect(anon.status).toBe(401);

    const link = await authed(user).post('/api/auth/extension-link');
    expect(link.status).toBe(200);
    const code = link.body.code as string;
    expect(code.length).toBeGreaterThanOrEqual(32);

    // Malformed codes die at the schema; unknown well-formed codes at the store.
    const malformed = await request(app).post('/api/auth/extension-session').send({ code: 'nope' });
    expect(malformed.status).toBe(400);
    const unknown = await request(app)
      .post('/api/auth/extension-session')
      .send({ code: generateToken(32) });
    expect(unknown.status).toBe(401);

    // The real code exchanges for a session - Bearer, no cookie.
    const session = await request(app).post('/api/auth/extension-session').send({ code });
    expect(session.status).toBe(200);
    expect(session.body.sessionToken).toBeTruthy();
    expect(session.body.user.email).toBe(user.email);
    expect(session.body.user.wrappedVaultKey).toBeTruthy();
    expect(session.headers['set-cookie']).toBeUndefined();

    // The session is fully live.
    const me = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${session.body.sessionToken}`);
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe(user.email);

    // Replay: a consumed link code can never mint a second session.
    const replay = await request(app).post('/api/auth/extension-session').send({ code });
    expect(replay.status).toBe(401);
  });

  it('replaces the previous link code when a new one is minted', async () => {
    const user = await makeSeededUser('ext2');
    const first = await authed(user).post('/api/auth/extension-link');
    const second = await authed(user).post('/api/auth/extension-link');
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);

    // Only the newest code works.
    const stale = await request(app).post('/api/auth/extension-session').send({ code: first.body.code });
    expect(stale.status).toBe(401);
    const fresh = await request(app).post('/api/auth/extension-session').send({ code: second.body.code });
    expect(fresh.status).toBe(200);
  });
});

describe('vault trash', () => {
  it('soft-deletes, hides from the vault, restores, then permanently deletes', async () => {
    const user = await makeSeededUser('trash');

    const created = await authed(user)
      .post('/api/secrets')
      .send({ title: 'Trashed item', category: 'LOGIN', ...fakeCiphertextPayload() });
    const secretId = created.body.secret.id as string;

    // Delete moves it to the trash; the vault no longer sees it.
    expect((await authed(user).delete(`/api/secrets/${secretId}`)).status).toBe(204);
    expect((await authed(user).get(`/api/secrets/${secretId}`)).status).toBe(404);
    const list = await authed(user).get('/api/secrets');
    expect(list.body.items.some((item: { id: string }) => item.id === secretId)).toBe(false);

    // The trash listing shows it; dashboard excludes it from live counts.
    const trash = await authed(user).get('/api/secrets/trash');
    expect(trash.body.items.some((item: { id: string }) => item.id === secretId)).toBe(true);
    const dash = await authed(user).get('/api/dashboard');
    expect(dash.body.counts.secrets).toBe(0);
    expect(dash.body.counts.trash).toBe(1);

    // Restore brings it back fully intact.
    const restored = await authed(user).post(`/api/secrets/${secretId}/restore`);
    expect(restored.status).toBe(200);
    expect((await authed(user).get(`/api/secrets/${secretId}`)).status).toBe(200);

    // Trash it again, then purge permanently.
    await authed(user).delete(`/api/secrets/${secretId}`);
    expect((await authed(user).delete(`/api/secrets/${secretId}/permanent`)).status).toBe(204);
    expect(await prisma.secret.findUnique({ where: { id: secretId } })).toBeNull();
    const trashAfter = await authed(user).get('/api/secrets/trash');
    expect(trashAfter.body.items).toHaveLength(0);
  });

  it('keeps the trash scoped per user', async () => {
    const alice = await makeSeededUser('trash-owner');
    const bob = await makeSeededUser('trash-intruder');

    const created = await authed(alice)
      .post('/api/secrets')
      .send({ title: 'Alice trash', category: 'CUSTOM', ...fakeCiphertextPayload() });
    const secretId = created.body.secret.id as string;
    await authed(alice).delete(`/api/secrets/${secretId}`);

    // Bob cannot see, restore or purge Alice's trashed item.
    const bobTrash = await authed(bob).get('/api/secrets/trash');
    expect(bobTrash.body.items.some((item: { id: string }) => item.id === secretId)).toBe(false);
    expect((await authed(bob).post(`/api/secrets/${secretId}/restore`)).status).toBe(404);
    expect((await authed(bob).delete(`/api/secrets/${secretId}/permanent`)).status).toBe(404);
  });
});

describe('activity log', () => {
  it('records security events without secret values', async () => {
    const user = await makeSeededUser('activity');

    await authed(user)
      .post('/api/secrets')
      .send({ title: 'Logged item', category: 'API_KEY', ...fakeCiphertextPayload() });

    const activity = await authed(user).get('/api/activity');
    expect(activity.status).toBe(200);

    const types = activity.body.items.map((event: { type: string }) => event.type);
    expect(types).toContain('SECRET_CREATED');

    // No event body may contain ciphertext or field values.
    for (const event of activity.body.items) {
      expect(JSON.stringify(event)).not.toContain('ciphertext');
    }
  });
});

/** A structurally valid raw uncompressed P-256 point (not necessarily on-curve). */
function fakeP256Point(): string {
  return Buffer.concat([Buffer.from([4]), randomBytes(64)]).toString('base64');
}

describe('secure sharing', () => {
  const shareKey = () => ({
    sharePublicKey: fakeP256Point(),
    sharePrivateKeyWrapped: {
      nonce: randomBytes(12).toString('base64'),
      ciphertext: randomBytes(48).toString('base64'),
    },
  });

  const sharePayload = (email: string) => ({
    recipientEmail: email,
    title: 'Shared login',
    category: 'LOGIN',
    senderPublicKey: fakeP256Point(),
    nonce: randomBytes(12).toString('base64'),
    ciphertext: randomBytes(80).toString('base64'),
  });

  it('publishes a share key, then supports the full send/accept lifecycle', async () => {
    const sender = await makeSeededUser('share-sender');
    const recipient = await makeSeededUser('share-recipient');

    // Recipient without a published key cannot be looked up for sharing.
    const early = await authed(sender).get(`/api/shares/lookup?email=${encodeURIComponent(recipient.email)}`);
    expect(early.status).toBe(409);

    // Publish the recipient's share key.
    const publish = await authed(recipient).put('/api/account/share-key').send(shareKey());
    expect(publish.status).toBe(200);

    const lookup = await authed(sender).get(`/api/shares/lookup?email=${encodeURIComponent(recipient.email)}`);
    expect(lookup.status).toBe(200);
    expect(lookup.body.sharePublicKey).toBeTruthy();

    // Send the share - ciphertext only.
    const sent = await authed(sender).post('/api/shares').send({ ...sharePayload(recipient.email), expiresInDays: 7 });
    expect(sent.status).toBe(201);
    const shareId = sent.body.id as string;

    // Recipient sees it incoming; sender sees it outgoing.
    const inbox = await authed(recipient).get('/api/shares');
    const hit = inbox.body.incoming.find((s: { id: string }) => s.id === shareId);
    expect(hit).toBeTruthy();
    expect(hit.peer.email).toBe(sender.email);
    const outbox = await authed(sender).get('/api/shares');
    expect(outbox.body.outgoing.some((s: { id: string }) => s.id === shareId)).toBe(true);

    // Sender cannot accept their own share; recipient accepts.
    expect((await authed(sender).post(`/api/shares/${shareId}/accept`)).status).toBe(404);
    const accepted = await authed(recipient).post(`/api/shares/${shareId}/accept`);
    expect(accepted.status).toBe(200);

    const after = await authed(sender).get('/api/shares');
    expect(after.body.outgoing.find((s: { id: string }) => s.id === shareId).status).toBe('ACCEPTED');
  });

  it('lets the sender revoke and the recipient decline', async () => {
    const sender = await makeSeededUser('share-revoker');
    const recipient = await makeSeededUser('share-decliner');
    await authed(recipient).put('/api/account/share-key').send(shareKey());

    const first = await authed(sender).post('/api/shares').send(sharePayload(recipient.email));
    expect(first.status).toBe(201);
    expect((await authed(sender).delete(`/api/shares/${first.body.id}`)).status).toBe(200);

    const second = await authed(sender).post('/api/shares').send(sharePayload(recipient.email));
    expect(second.status).toBe(201);
    expect((await authed(recipient).post(`/api/shares/${second.body.id}/decline`)).status).toBe(200);

    const inbox = await authed(recipient).get('/api/shares');
    expect(inbox.body.incoming).toHaveLength(0);
  });

  it('rejects sharing to yourself and to unknown accounts', async () => {
    const user = await makeSeededUser('share-self');
    await authed(user).put('/api/account/share-key').send(shareKey());

    const self = await authed(user).post('/api/shares').send(sharePayload(user.email));
    expect(self.status).toBe(400);
    expect(self.body.error.code).toBe('self_share');

    const ghost = await authed(user).post('/api/shares').send(sharePayload(uniqueEmail('share-ghost')));
    expect(ghost.status).toBe(404);
  });

  it('requires authentication', async () => {
    expect((await request(app).get('/api/shares')).status).toBe(401);
    expect((await request(app).post('/api/shares').send({})).status).toBe(401);
  });
});

describe('emergency access', () => {
  const grantBody = (email: string, waitDays = 7) => ({
    granteeEmail: email,
    waitDays,
    handoverSenderPublicKey: fakeP256Point(),
    handoverNonce: randomBytes(12).toString('base64'),
    handoverCiphertext: randomBytes(60).toString('base64'),
  });

  it('runs the full grant → request → wait → access lifecycle', async () => {
    const grantor = await makeSeededUser('em-grantor');
    const grantee = await makeSeededUser('em-grantee');
    await authed(grantee).put('/api/account/share-key').send({
      sharePublicKey: fakeP256Point(),
      sharePrivateKeyWrapped: { nonce: randomBytes(12).toString('base64'), ciphertext: randomBytes(40).toString('base64') },
    });

    // Grantor adds the trusted contact with a pre-wrapped handover key.
    const created = await authed(grantor).post('/api/emergency').send(grantBody(grantee.email));
    expect(created.status).toBe(201);
    const grantId = created.body.id as string;

    // Grantee sees it pending and requests access.
    const list = await authed(grantee).get('/api/emergency');
    expect(list.body.asGrantee[0].status).toBe('PENDING');
    expect((await authed(grantee).post(`/api/emergency/${grantId}/request`)).status).toBe(200);

    // During the wait the handover is NOT released.
    const early = await authed(grantee).post(`/api/emergency/${grantId}/access`);
    expect(early.status).toBe(409);

    // Grantor approves early → waitUntil collapses to now → key releases.
    expect((await authed(grantor).post(`/api/emergency/${grantId}/approve`)).status).toBe(200);
    const access = await authed(grantee).post(`/api/emergency/${grantId}/access`);
    expect(access.status).toBe(200);
    expect(access.body.ciphertext).toBeTruthy();
    expect(access.body.senderPublicKey).toBeTruthy();

    // Now APPROVED, the read-only vault export serves the grantor's ciphertext.
    await authed(grantor).post('/api/secrets').send({ title: 'Estate login', category: 'LOGIN', ...fakeCiphertextPayload() });
    const vault = await authed(grantee).get(`/api/emergency/${grantId}/vault`);
    expect(vault.status).toBe(200);
    expect(vault.body.secrets.some((s: { title: string }) => s.title === 'Estate login')).toBe(true);

    // Grantor can still cancel, ending access.
    expect((await authed(grantor).post(`/api/emergency/${grantId}/cancel`)).status).toBe(200);
    expect((await authed(grantee).get(`/api/emergency/${grantId}/vault`)).status).toBe(404);
  });

  it('releases instantly when the wait period is zero', async () => {
    const grantor = await makeSeededUser('em-instant');
    const grantee = await makeSeededUser('em-instantee');
    await authed(grantee).put('/api/account/share-key').send({
      sharePublicKey: fakeP256Point(),
      sharePrivateKeyWrapped: { nonce: randomBytes(12).toString('base64'), ciphertext: randomBytes(40).toString('base64') },
    });

    const created = await authed(grantor).post('/api/emergency').send(grantBody(grantee.email, 0));
    expect(created.status).toBe(201);
    const grantId = created.body.id as string;

    expect((await authed(grantee).post(`/api/emergency/${grantId}/request`)).status).toBe(200);
    // No wait - the handover releases on the very next call.
    const access = await authed(grantee).post(`/api/emergency/${grantId}/access`);
    expect(access.status).toBe(200);
    expect(access.body.ciphertext).toBeTruthy();
  });

  it('lets the grantor cancel a waiting request before release', async () => {
    const grantor = await makeSeededUser('em-canceller');
    const grantee = await makeSeededUser('em-cancellee');
    await authed(grantee).put('/api/account/share-key').send({
      sharePublicKey: fakeP256Point(),
      sharePrivateKeyWrapped: { nonce: randomBytes(12).toString('base64'), ciphertext: randomBytes(40).toString('base64') },
    });

    const created = await authed(grantor).post('/api/emergency').send(grantBody(grantee.email));
    const grantId = created.body.id as string;
    await authed(grantee).post(`/api/emergency/${grantId}/request`);

    expect((await authed(grantor).post(`/api/emergency/${grantId}/cancel`)).status).toBe(200);
    expect((await authed(grantee).post(`/api/emergency/${grantId}/access`)).status).toBe(404);
  });

  it('blocks a contact without a published share key and duplicate grants', async () => {
    const grantor = await makeSeededUser('em-dup');
    const grantee = await makeSeededUser('em-nokey');

    expect((await authed(grantor).post('/api/emergency').send(grantBody(grantee.email))).status).toBe(409);

    await authed(grantee).put('/api/account/share-key').send({
      sharePublicKey: fakeP256Point(),
      sharePrivateKeyWrapped: { nonce: randomBytes(12).toString('base64'), ciphertext: randomBytes(40).toString('base64') },
    });
    expect((await authed(grantor).post('/api/emergency').send(grantBody(grantee.email))).status).toBe(201);
    expect((await authed(grantor).post('/api/emergency').send(grantBody(grantee.email))).status).toBe(409);
  });

  it('rejects adding yourself as a trusted contact', async () => {
    const user = await makeSeededUser('em-self');
    const res = await authed(user).post('/api/emergency').send(grantBody(user.email));
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('self_grant');
  });
});

describe('passkeys', () => {
  const passkeyBody = () => ({
    credentialId: randomBytes(32).toString('base64url'),
    name: 'Chrome on Windows',
    prfSalt: randomBytes(32).toString('base64'),
    wrappedVaultKey: {
      nonce: randomBytes(12).toString('base64'),
      ciphertext: randomBytes(48).toString('base64'),
    },
  });

  it('enrolls, lists and removes a passkey per user', async () => {
    const user = await makeSeededUser('passkey-owner');
    const intruder = await makeSeededUser('passkey-intruder');

    const created = await authed(user).post('/api/account/passkeys').send(passkeyBody());
    expect(created.status).toBe(201);
    const passkeyId = created.body.id as string;

    const list = await authed(user).get('/api/account/passkeys');
    expect(list.body.passkeys).toHaveLength(1);
    expect(list.body.passkeys[0].name).toBe('Chrome on Windows');

    // Another user cannot see or delete it.
    const otherList = await authed(intruder).get('/api/account/passkeys');
    expect(otherList.body.passkeys).toHaveLength(0);
    expect((await authed(intruder).delete(`/api/account/passkeys/${passkeyId}`)).status).toBe(404);

    expect((await authed(user).delete(`/api/account/passkeys/${passkeyId}`)).status).toBe(200);
    const after = await authed(user).get('/api/account/passkeys');
    expect(after.body.passkeys).toHaveLength(0);
  });

  it('rejects duplicate credential ids', async () => {
    const user = await makeSeededUser('passkey-dup');
    const body = passkeyBody();
    expect((await authed(user).post('/api/account/passkeys').send(body)).status).toBe(201);
    expect((await authed(user).post('/api/account/passkeys').send(body)).status).toBe(409);
  });
});

describe('activity heatmap', () => {
  it('aggregates own events per day and hides other users', async () => {
    const user = await makeSeededUser('heatmap');
    const intruder = await makeSeededUser('heatmap-other');

    await authed(user)
      .post('/api/secrets')
      .send({ title: 'Heatmapped item', category: 'LOGIN', ...fakeCiphertextPayload() });

    const res = await authed(user).get('/api/activity/heatmap?days=30');
    expect(res.status).toBe(200);

    const today = new Date().toISOString().slice(0, 10);
    expect(res.body.days[today]).toBeGreaterThanOrEqual(1);
    for (const [day, count] of Object.entries<number>(res.body.days)) {
      expect(day).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(count).toBeGreaterThan(0);
    }

    // The intruder's own (empty) heatmap must not see our event.
    const other = await authed(intruder).get('/api/activity/heatmap?days=30');
    expect(other.status).toBe(200);
    expect(other.body.days[today] ?? 0).toBe(0);
  });
});

describe('session geo label', () => {
  it('stores the edge country header on new sessions', async () => {
    const email = uniqueEmail('geo');
    const agent = request.agent(app);
    const signup = await agent
      .post('/api/auth/signup')
      .set('x-vercel-ip-country', 'in')
      .send({
        email,
        authVerifier: fakeAuthVerifier(),
        kdf: TEST_KDF,
        wrappedVaultKey: fakeWrappedVaultKey(),
        serverWrappedVaultKey: fakeServerWrappedVaultKey(),
      });
    expect(signup.status).toBe(201);
    createdEmails.push(email);
    // Sessions sit behind the verification gate - verify via the dev OTP
    // obtained from an explicit resend (signup no longer mails one).
    const resend = await agent
      .post('/api/auth/resend-verification')
      .set('X-CSRF-Token', signup.body.csrfToken);
    await agent
      .post('/api/auth/verify-email-code')
      .set('X-CSRF-Token', signup.body.csrfToken)
      .send({ code: resend.body.previewCode });

    const sessions = await agent.get('/api/auth/sessions');
    expect(sessions.status).toBe(200);
    expect(sessions.body.items[0].country).toBe('IN');
  });

  it('normalises bogus geo header values to null', async () => {
    const email = uniqueEmail('geo-bad');
    const agent = request.agent(app);
    const signup = await agent
      .post('/api/auth/signup')
      .set('x-vercel-ip-country', 'not-a-country')
      .send({
        email,
        authVerifier: fakeAuthVerifier(),
        kdf: TEST_KDF,
        wrappedVaultKey: fakeWrappedVaultKey(),
        serverWrappedVaultKey: fakeServerWrappedVaultKey(),
      });
    expect(signup.status).toBe(201);
    createdEmails.push(email);
    const resend = await agent
      .post('/api/auth/resend-verification')
      .set('X-CSRF-Token', signup.body.csrfToken);
    await agent
      .post('/api/auth/verify-email-code')
      .set('X-CSRF-Token', signup.body.csrfToken)
      .send({ code: resend.body.previewCode });

    const sessions = await agent.get('/api/auth/sessions');
    expect(sessions.body.items[0].country).toBeNull();
  });
});
