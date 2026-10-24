import type { Request } from 'express';
import { z } from 'zod';
import { ApiError } from './http.js';
import { idSchema } from './validation.js';

/**
 * Coarse IP label kept for session/activity display. The last IPv4 octet (or
 * the IPv6 interface part) is dropped so the vault does not accumulate precise
 * location data about its own user.
 */
export function getIpLabel(req: Request): string | null {
  const raw = req.ip ?? req.socket.remoteAddress ?? null;
  if (!raw) return null;

  const ip = raw.startsWith('::ffff:') ? raw.slice(7) : raw;

  if (ip.includes('.')) {
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.x`;
    return ip.slice(0, 32);
  }

  const groups = ip.split(':').filter(Boolean);
  if (groups.length >= 3) return `${groups.slice(0, 3).join(':')}::`;
  return ip.slice(0, 32);
}

export function getUserAgent(req: Request): string | null {
  const ua = req.get('user-agent');
  if (!ua) return null;
  return ua.slice(0, 255);
}

/**
 * Coarse ISO-3166 alpha-2 country for the sign-in map. Read from the edge
 * provider's geo header (Vercel injects `x-vercel-ip-country`; Cloudflare
 * `cf-ipcountry` as a fallback) so no IP→geo lookup or third-party call is
 * needed and we never store more than a country code. `XX`/`T1` mean "unknown"
 * at the edge and are normalised to null; anything not matching alpha-2 is
 * dropped - the header is still request input, not trusted data.
 */
export function getCountryCode(req: Request): string | null {
  const raw = req.get('x-vercel-ip-country') ?? req.get('cf-ipcountry') ?? null;
  if (!raw) return null;
  const code = raw.trim().toUpperCase();
  return /^[A-Z]{2}$/.test(code) && code !== 'XX' && code !== 'T1' ? code : null;
}

/** Validates a request body and returns a typed result (ZodError -> 400 upstream). */
export function parseBody<T extends z.ZodType>(schema: T, req: Request): z.output<T> {
  return schema.parse(req.body);
}

/** Validates the query string. Express 5 exposes `req.query` as a getter, so it is never mutated. */
export function parseQuery<T extends z.ZodType>(schema: T, req: Request): z.output<T> {
  return schema.parse(req.query);
}

/** Route params are always user input: never trust them as ownership proof. */
export function parseIdParam(req: Request, name = 'id'): string {
  const value = req.params[name];
  const result = idSchema.safeParse(value);
  if (!result.success) throw ApiError.notFound('Resource not found');
  return result.data;
}
