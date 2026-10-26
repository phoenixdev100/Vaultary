import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../generated/prisma/client.js';
import { env, isProduction } from '../config/env.js';

/**
 * Serverless-friendly Prisma singleton.
 *
 * Vercel functions are frozen between invocations rather than torn down, so the
 * client (and its small pg pool) is cached on `globalThis` to avoid opening a
 * new pool on every warm request. The pool is deliberately tiny in production
 * because many concurrent lambdas share one Postgres/Neon pooler.
 */
const globalForPrisma = globalThis as unknown as { vaultoryPrisma?: PrismaClient };

function createPrismaClient(): PrismaClient {
  const adapter = new PrismaPg({
    connectionString: env.DATABASE_URL,
    max: isProduction ? 3 : 10,
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 10_000,
  });

  return new PrismaClient({ adapter });
}

export const prisma: PrismaClient = globalForPrisma.vaultoryPrisma ?? createPrismaClient();

globalForPrisma.vaultoryPrisma = prisma;
