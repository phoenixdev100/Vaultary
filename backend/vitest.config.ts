import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Integration tests hit a real (dev) database and argon2id - give them room.
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // The Neon dev database is shared: serial execution avoids test cross-talk.
    fileParallelism: false,
    env: {
      NODE_ENV: 'test',
      LOG_LEVEL: 'silent',
      // Tests exercise cookies over plain http via supertest - a deploy-time
      // CROSS_SITE_COOKIES=true in .env would mark them Secure and the agent
      // would drop them (every authed request 401s). Pin it off here.
      CROSS_SITE_COOKIES: 'false',
    },
  },
});
