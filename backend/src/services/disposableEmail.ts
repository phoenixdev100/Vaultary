import { DISPOSABLE_DOMAINS } from './disposableDomains.generated.js';

/**
 * True when the address belongs to a known disposable/temp-mail provider.
 * Matches the bare domain and any parent - `x.yopmail.com` is caught by the
 * `yopmail.com` entry, so subdomain tricks don't bypass the check.
 */
export function isDisposableEmail(email: string): boolean {
  const at = email.lastIndexOf('@');
  if (at < 0) return false;
  let domain = email.slice(at + 1).toLowerCase();

  while (true) {
    if (DISPOSABLE_DOMAINS.has(domain)) return true;
    const dot = domain.indexOf('.');
    if (dot < 0) return false;
    domain = domain.slice(dot + 1);
  }
}
