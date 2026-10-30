/**
 * Vercel serverless entry point.
 *
 * `vercel.json` rewrites every path here; the default export is the ready
 * Express app from src/app.ts (module scope = created once per warm instance
 * and reused across invocations). There is no long-running process and no
 * in-memory state: sessions, rate-limit counters and everything else live in
 * Postgres.
 */
export { default } from '../src/app.js';
