import { createApp } from './app.js';
import { env } from './config/env.js';
import { logger } from './config/logger.js';
import { prisma } from './db/prisma.js';
import { verifyMailTransport } from './services/mailer.js';

const app = createApp();

// If a host (e.g. Vercel) treats this conventional filename as the function
// entrypoint, the default export is a valid request handler.
export default app;

// Only bind a port for real processes - on serverless the default export is
// the entry and a top-level listen() would race the function lifecycle.
if (!process.env.VERCEL) {
  const server = app.listen(env.PORT, () => {
    logger.info({ port: env.PORT, env: env.NODE_ENV }, 'Vaultory API listening');
    // Fires after listen so a slow/hung relay never delays the API coming up.
    void verifyMailTransport();
  });

  // Slow-loris / connection-abuse hardening (self-hosted path - on Vercel the
  // edge enforces these before a lambda is even invoked):
  server.headersTimeout = 20_000; // must be < requestTimeout
  server.requestTimeout = 60_000; // whole request must complete within a minute
  server.keepAliveTimeout = 65_000; // > typical LB idle timeout, avoids mid-flight kills
  server.maxRequestsPerSocket = 100; // recycle sockets so one connection can't pin a worker

  async function shutdown(signal: string): Promise<void> {
    logger.info({ signal }, 'Shutting down Vaultory API');
    server.close(() => undefined);
    await prisma.$disconnect().catch(() => undefined);
    process.exit(0);
  }

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}
