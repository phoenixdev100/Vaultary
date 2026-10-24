import { randomUUID } from 'node:crypto';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import express, { type Express } from 'express';
import helmet from 'helmet';
import { pinoHttp } from 'pino-http';
import { env, isTest } from './config/env.js';
import { logger } from './config/logger.js';
import { errorHandler, notFoundHandler } from './middleware/errors.js';
import { isAllowedOrigin, originGuard } from './middleware/originGuard.js';
import { generalLimiter } from './middleware/rateLimit.js';
import { apiRouter } from './routes/index.js';

export function createApp(): Express {
  const app = express();

  app.disable('x-powered-by');
  // Vercel and most PaaS platforms terminate TLS in front of the app.
  if (env.TRUST_PROXY) app.set('trust proxy', 1);

  app.use((req, _res, next) => {
    req.requestId = randomUUID();
    next();
  });

  if (!isTest) {
    app.use(
      pinoHttp({
        logger,
        genReqId: (req) => req.requestId ?? randomUUID(),
        customLogLevel: (_req, res, err) => {
          if (err || res.statusCode >= 500) return 'error';
          if (res.statusCode >= 400) return 'warn';
          return 'info';
        },
        // Request/response bodies are never logged; only method, path, status.
        serializers: {
          req: (req) => ({ id: req.id, method: req.method, url: req.url }),
          res: (res) => ({ statusCode: res.statusCode }),
        },
      }),
    );
  }

  app.use(
    helmet({
      // JSON API: a restrictive CSP belongs on the frontend deployment.
      contentSecurityPolicy: false,
      crossOriginResourcePolicy: { policy: 'same-site' },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );

  app.use(
    cors({
      origin(origin, callback) {
        // Same-origin / non-browser callers send no Origin header.
        if (!origin || isAllowedOrigin(origin)) {
          callback(null, true);
          return;
        }
        callback(null, false);
      },
      credentials: true,
      methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'Authorization'],
      maxAge: 600,
    }),
  );

  // Cheap request-hardening before any body work:
  // - absurdly long URLs (query-string floods) die here
  // - unsafe methods must carry a JSON body - blunts CSRF-ish form posts and
  //   junk content-types that would parse as nothing anyway
  app.use((req, res, next) => {
    if (req.url.length > 2048) {
      res.status(414).json({ error: { code: 'uri_too_long', message: 'Request URL is too long' } });
      return;
    }
    // A request that actually carries a body must declare it JSON - empty
    // POSTs (restore/accept/cancel style endpoints) send Content-Length: 0
    // and need no content-type; a form-urlencoded or binary blob never parses
    // into a valid body anyway.
    const contentLength = Number(req.headers['content-length'] ?? 0);
    const hasBody = contentLength > 0 || req.headers['transfer-encoding'] !== undefined;
    if (hasBody && req.is('application/json') !== 'application/json') {
      res
        .status(415)
        .json({ error: { code: 'unsupported_media_type', message: 'Content-Type must be application/json' } });
      return;
    }
    next();
  });

  // 4mb accommodates a 2 MiB encrypted attachment (~2.7mb base64) plus JSON
  // envelope. The per-field ciphertext cap does the real enforcement.
  app.use(express.json({ limit: '4mb' }));
  app.use(cookieParser());

  // Private, per-user data: never allow shared or browser-level caching.
  app.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Vary', 'Origin');
    next();
  });

  app.use(originGuard);
  if (!isTest) app.use(generalLimiter);

  app.use('/api', apiRouter);

  // A bare GET on the API root is almost always a person looking for the app
  // - point them at the health check instead of a bare 404.
  app.get('/', (_req, res) => {
    res.json({ name: 'Vaultory API', status: 'ok', health: '/api/health' });
  });

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}

/**
 * Serverless-ready default export. Vercel's backend-framework detection may
 * treat this conventional filename as a function entrypoint and requires a
 * default export that is a request handler or server - so the configured app
 * is exported alongside the factory. Local/self-hosted paths keep using
 * createApp() through server.ts.
 */
const serverlessApp = createApp();
// Vercel always fronts lambdas with X-Forwarded-For - trusting the proxy gives
// real client IPs to rate limiting and session geo labels.
serverlessApp.set('trust proxy', 1);
export default serverlessApp;
