import { pino } from 'pino';
import { env, isProduction } from './env.js';

/**
 * Paths that must never reach the log output. Vaultory only ever receives
 * ciphertext, but request bodies also carry authentication verifiers and
 * wrapped key material, so they are redacted defensively.
 */
const redactPaths = [
  'req.headers.cookie',
  'req.headers.authorization',
  'req.headers["x-csrf-token"]',
  'res.headers["set-cookie"]',
  'password',
  'authVerifier',
  'currentAuthVerifier',
  'newAuthVerifier',
  'wrappedVaultKey',
  'newWrappedVaultKey',
  'ciphertext',
  'nonce',
  'token',
  'resetToken',
  '*.password',
  '*.authVerifier',
  '*.ciphertext',
  '*.nonce',
  '*.token',
];

export const logger = pino({
  level: env.LOG_LEVEL,
  redact: { paths: redactPaths, censor: '[redacted]' },
  base: { service: 'vaultory-api' },
  transport: isProduction
    ? undefined
    : {
        target: 'pino-pretty',
        options: { colorize: true, translateTime: 'HH:MM:ss', ignore: 'pid,hostname,service' },
      },
});
