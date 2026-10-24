import 'dotenv/config';
import { z } from 'zod';

const bool = z
  .union([z.boolean(), z.enum(['true', 'false', '1', '0'])])
  .transform((value) => value === true || value === 'true' || value === '1');

/** An empty .env value (SMTP_PASS="") means "not set", not "invalid". */
const optString = z.preprocess(
  (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
  z.string().min(1).optional(),
);

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),

  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  DIRECT_URL: z.string().min(1).optional(),

  /// HMAC key used to hash session / reset tokens before they are stored.
  SESSION_SECRET: z.string().min(32, 'SESSION_SECRET must be at least 32 characters'),
  /// Root secret for the vault-key escrow: derives the server ECDH keypair that
  /// lets a verified password reset recover the vault key. Rotating it orphans
  /// every escrowed key, so treat it like the database itself.
  VAULT_WRAP_SECRET: z.string().min(32, 'VAULT_WRAP_SECRET must be at least 32 characters'),
  SESSION_TTL_DAYS: z.coerce.number().int().positive().max(365).default(30),
  /// Minutes of inactivity before the vault key is wiped, applied to new
  /// accounts. 0 means "never auto-lock"; users can override in Settings.
  AUTO_LOCK_MINUTES: z.coerce.number().int().min(0).max(480).default(15),
  COOKIE_DOMAIN: z.string().min(1).optional(),
  /// Set when the API and the frontend are served from different sites.
  CROSS_SITE_COOKIES: bool.default(false),
  TRUST_PROXY: bool.default(false),

  /// Public URL of the frontend, used to build links inside emails.
  APP_URL: z.string().url().default('http://localhost:5173'),
  /// Comma separated list of browser origins allowed to call this API.
  CORS_ORIGINS: z
    .string()
    .default('http://localhost:5173')
    .transform((value) =>
      value
        .split(',')
        .map((origin) => origin.trim().replace(/\/$/, ''))
        .filter(Boolean),
    ),

  REQUIRE_EMAIL_VERIFICATION: bool.default(false),
  /// 'console' prints links to the API log (dev only), 'resend' uses the
  /// Resend API, 'smtp' sends through any standard SMTP account the user
  /// configures below (Gmail app password, Outlook, a provider relay, ...).
  EMAIL_TRANSPORT: z.enum(['console', 'resend', 'smtp']).default('console'),
  EMAIL_FROM: z.string().default('Vaultory <no-reply@vaultory.local>'),
  RESEND_API_KEY: optString,
  SMTP_HOST: optString,
  SMTP_PORT: z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    z.coerce.number().int().min(1).max(65535).optional(),
  ),
  SMTP_SECURE: bool.default(false),
  SMTP_USER: optString,
  SMTP_PASS: optString,
});

export type Env = z.infer<typeof schema>;

function load(): Env {
  const parsed = schema.safeParse(process.env);

  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    // Never print the values, only which variables are wrong.
    throw new Error(`Invalid environment configuration:\n${details}`);
  }

  const env = parsed.data;

  if (env.EMAIL_TRANSPORT === 'resend' && !env.RESEND_API_KEY) {
    throw new Error('Invalid environment configuration: RESEND_API_KEY is required when EMAIL_TRANSPORT=resend');
  }

  if (env.EMAIL_TRANSPORT === 'smtp' && (!env.SMTP_HOST || !env.SMTP_USER || !env.SMTP_PASS)) {
    throw new Error(
      'Invalid environment configuration: SMTP_HOST, SMTP_USER and SMTP_PASS are required when EMAIL_TRANSPORT=smtp',
    );
  }

  if (env.NODE_ENV === 'production' && env.EMAIL_TRANSPORT === 'console' && env.REQUIRE_EMAIL_VERIFICATION) {
    throw new Error(
      'Invalid environment configuration: REQUIRE_EMAIL_VERIFICATION needs a real EMAIL_TRANSPORT in production',
    );
  }

  return env;
}

export const env = load();

export const isProduction = env.NODE_ENV === 'production';
export const isTest = env.NODE_ENV === 'test';
