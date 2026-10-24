import 'dotenv/config';
import { defineConfig } from 'prisma/config';

/**
 * CLI-only configuration (migrate / studio).
 *
 * The application itself connects through the `pg` driver adapter in
 * `src/db/prisma.ts` using the pooled `DATABASE_URL`. Migrations need a real
 * (non-pooled) connection for DDL and advisory locks, so the CLI prefers
 * `DIRECT_URL` and only falls back to `DATABASE_URL`.
 */
export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
  },
  datasource: {
    url: process.env.DIRECT_URL ?? process.env.DATABASE_URL ?? '',
  },
});
