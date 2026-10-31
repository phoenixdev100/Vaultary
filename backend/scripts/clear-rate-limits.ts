import { prisma } from '../src/db/prisma.js';

/**
 * Dev/test helper: drops every rate-limit bucket. Buckets are ephemeral
 * counters (attempts per IP/email window) - deleting them is safe and only
 * resets throttling state. Used by the e2e suite before browser runs so
 * repeated signups from 127.0.0.1 do not exhaust the production limits.
 */
async function main() {
  const { count } = await prisma.rateLimitCounter.deleteMany({});
  console.log(`Cleared ${count} rate-limit bucket(s)`);
}

main()
  .catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => void prisma.$disconnect());
