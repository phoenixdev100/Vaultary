/**
 * Sends a real test email through the configured transport.
 * Usage: npx tsx scripts/test-email.ts you@example.com
 */
import { env } from '../src/config/env.js';
import { mailer } from '../src/services/mailer.js';

async function main(): Promise<void> {
  const to = process.argv[2];
  if (!to) {
    console.error('Usage: npx tsx scripts/test-email.ts <recipient@example.com>');
    process.exit(1);
  }

  console.log(`Transport: ${env.EMAIL_TRANSPORT}`);
  console.log(`From: ${env.EMAIL_FROM}`);
  console.log(`To:   ${to}`);

  const result = await mailer.send(
    {
      to,
      subject: 'Vaultory SMTP test',
      text: 'If you can read this, email delivery works.',
      html: '<p>If you can read this, <strong>email delivery works</strong>.</p>',
    },
    `${env.APP_URL}/test`,
  );

  console.log('Result:', JSON.stringify(result));
  process.exit(result.delivered ? 0 : 1);
}

void main();
