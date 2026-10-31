// Regenerates src/services/disposableDomains.generated.ts from the upstream
// blocklist. Run: node scripts/gen-disposable-domains.mjs
import { writeFileSync } from 'node:fs';

const SOURCE = 'https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blocklist.conf';

const res = await fetch(SOURCE);
if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);
const domains = [...new Set(
  (await res.text()).split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')),
)];

const out =
  '/**\n * Disposable/temp-mail domain blocklist.\n * Source: github.com/martenson/disposable-email-domains (blocklist.conf)\n * Regenerate: node scripts/gen-disposable-domains.mjs\n */\n' +
  'export const DISPOSABLE_DOMAINS: ReadonlySet<string> = new Set([\n' +
  domains.map((d) => '  ' + JSON.stringify(d) + ',').join('\n') +
  '\n]);\n';

writeFileSync(new URL('../src/services/disposableDomains.generated.ts', import.meta.url), out);
console.log(`Wrote ${domains.length} domains`);
