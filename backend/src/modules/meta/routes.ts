import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { Router } from 'express';
import { ApiError } from '../../utils/http.js';
import { getAuth, requireAuth, requireVerifiedEmail } from '../../middleware/auth.js';
import { consumeRateLimit } from '../../middleware/rateLimit.js';

/**
 * Favicon proxy: the browser asks us for a site's icon and we fetch it, so a
 * third party (e.g. Google's favicon service) never learns which sites the
 * vault holds. Titles are already plaintext metadata server-side, so the
 * domain arriving here does not widen the trust boundary.
 *
 * SSRF hardening: the host must be a public-looking hostname - no IP literals,
 * no local/internal names, no ports or credentials. Redirects are followed
 * manually with the same validation applied to every hop, and responses are
 * capped in size and time.
 */
export const metaRouter = Router();

metaRouter.use(requireAuth, requireVerifiedEmail);

const MAX_ICON_BYTES = 64 * 1024;
const FETCH_TIMEOUT_MS = 3_000;
const MAX_REDIRECTS = 2;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_MAX = 500;

interface CachedIcon {
  body: Buffer;
  contentType: string;
  fetchedAt: number;
}
const cache = new Map<string, CachedIcon>();

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const BLOCKED_TLDS = /\.(localhost|local|internal|intranet|home|lan|corp|test|invalid|example)$/i;

function publicHostname(raw: string): string | null {
  const domain = raw.trim().toLowerCase();
  if (!HOSTNAME.test(domain) || BLOCKED_TLDS.test(domain)) return null;
  // IP literals can never match HOSTNAME, but reject explicitly anyway.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain) || domain.includes(':')) return null;
  return domain;
}

/**
 * Rejects non-public addresses: loopback, RFC1918, link-local, CGNAT,
 * multicast and reserved ranges. A hostname is only fetched when *every*
 * address it resolves to is public, which blocks DNS answers pointing at
 * internal infrastructure. A residual TOCTOU window remains (the fetch
 * re-resolves) - documented in docs/security.md.
 */
function isPublicIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) {
    const parts = ip.split('.').map(Number);
    const a = parts[0] ?? -1;
    const b = parts[1] ?? -1;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 192 && (b === 0 || b === 88)) return false;
    if (a === 198 && (b === 18 || b === 19 || b === 51)) return false;
    if (a === 203 && b === 0) return false;
    return true;
  }
  if (version === 6) {
    const groups = ipv6Groups(ip.toLowerCase());
    if (!groups) return false;
    const [g0, g1, g2, g3, g4, g5, g6, g7] = groups as [
      number, number, number, number, number, number, number, number,
    ];
    if (groups.every((group) => group === 0)) return false; // :: unspecified
    // Transition mechanisms that embed an IPv4 address in the low bits:
    // ::/96 compatible, ::ffff:/96 mapped, 64:ff9b::/96 NAT64, 2002::/16 6to4.
    if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0) {
      if (g5 === 0 || g5 === 0xffff) {
        return isPublicIp(`${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`);
      }
      return false;
    }
    if (g0 === 0x0064 && g1 === 0xff9b) return false; // NAT64 - embedded v4
    if (g0 === 0x2002) return false; // 6to4 - embedded v4
    if (g0 === 0x2001 && (g1 === 0x0000 || g1 === 0x0db8)) return false; // Teredo / doc range
    if ((g0 & 0xffc0) === 0xfe80) return false; // fe80::/10 link-local
    if ((g0 & 0xfe00) === 0xfc00) return false; // fc00::/7 ULA
    if ((g0 & 0xff00) === 0xff00) return false; // ff00::/8 multicast
    return true;
  }
  return false;
}

/** Expands a valid IPv6 literal (incl. `::` and dotted-quad tails) to 8 hex groups. */
function ipv6Groups(ip: string): number[] | null {
  let work = ip;
  const dotted = /:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(work);
  const dottedTail = dotted?.[1];
  if (dotted && dottedTail) {
    const octets = dottedTail.split('.').map(Number) as [number, number, number, number];
    if (octets.some((n) => n > 255)) return null;
    const [a, b, c, d] = octets;
    work = `${work.slice(0, dotted.index)}:${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = work.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ?? '';
  const right = halves[1] ?? '';
  const head = left === '' ? [] : left.split(':');
  const tail = halves.length === 2 ? (right === '' ? [] : right.split(':')) : [];
  if (halves.length === 1 && head.length !== 8) return null;
  const groups = [...head, ...Array<number>(8 - head.length - tail.length).fill(0), ...tail];
  if (groups.length !== 8) return null;
  const parsed = groups.map((group) => (group === '' ? 0 : parseInt(String(group), 16)));
  return parsed.every((n) => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? parsed : null;
}

/** Resolves the domain and requires every answer to be a public address. */
async function resolvesPublic(domain: string): Promise<boolean> {
  try {
    const addresses = await lookup(domain, { all: true, verbatim: true });
    return addresses.length > 0 && addresses.every((entry) => isPublicIp(entry.address));
  } catch {
    return false;
  }
}

async function fetchIcon(url: URL, redirectsLeft: number): Promise<{ body: Buffer; type: string } | null> {
  const response = await fetch(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    headers: { 'User-Agent': 'VaultoryFaviconBot/1.0', Accept: 'image/*,*/*;q=0.5' },
  });

  if (response.status >= 300 && response.status < 400 && redirectsLeft > 0) {
    const location = response.headers.get('location');
    if (!location) return null;
    const next = new URL(location, url);
    if (next.protocol !== 'https:' || !publicHostname(next.hostname)) return null;
    if (!(await resolvesPublic(next.hostname))) return null;
    return fetchIcon(next, redirectsLeft - 1);
  }

  if (!response.ok) return null;
  const type = response.headers.get('content-type')?.split(';')[0]?.trim() ?? 'image/x-icon';
  if (!type.startsWith('image/') && type !== 'application/octet-stream') return null;

  const length = Number(response.headers.get('content-length') ?? 0);
  if (length > MAX_ICON_BYTES) return null;

  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length === 0 || buffer.length > MAX_ICON_BYTES) return null;
  return { body: buffer, type };
}

metaRouter.get('/favicon', async (req, res) => {
  const { user } = getAuth(req);
  const raw = req.query.domain;
  const domain = publicHostname(typeof raw === 'string' ? raw : '');
  if (!domain) throw ApiError.badRequest('That is not a public hostname.');

  const hit = cache.get(domain);
  if (hit && Date.now() - hit.fetchedAt < CACHE_TTL_MS) {
    res.set({ 'Content-Type': hit.contentType, 'Cache-Control': 'private, max-age=86400', 'X-Content-Type-Options': 'nosniff' });
    res.send(hit.body);
    return;
  }

  // Only outbound fetches count against the budget; cached icons are free.
  await consumeRateLimit({ scope: 'favicon', limit: 120, windowMs: 60 * 60 * 1000 }, user.id);

  // DNS-level SSRF defence: never fetch a name that resolves internally.
  if (!(await resolvesPublic(domain))) {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No icon found.' } });
    return;
  }

  // Timeouts/DNS errors just mean "no icon" to the client.
  const icon = await fetchIcon(new URL(`https://${domain}/favicon.ico`), MAX_REDIRECTS).catch(() => null);

  if (!icon) {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No icon found.' } });
    return;
  }

  if (cache.size >= CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest) cache.delete(oldest);
  }
  cache.set(domain, { body: icon.body, contentType: icon.type, fetchedAt: Date.now() });

  res.set({ 'Content-Type': icon.type, 'Cache-Control': 'private, max-age=86400', 'X-Content-Type-Options': 'nosniff' });
  res.send(icon.body);
});
