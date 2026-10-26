import nodemailer from 'nodemailer';
import { env, isProduction } from '../config/env.js';
import { logger } from '../config/logger.js';

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export interface MailResult {
  /** True only when a provider actually accepted the message. */
  delivered: boolean;
  transport: string;
  /** Development-only echo of the action link so local flows are testable. */
  previewUrl?: string;
}

export interface MailTransport {
  name: string;
  send(message: MailMessage, actionUrl?: string): Promise<MailResult>;
}

/**
 * Development transport. It does NOT send email - it prints the link to the
 * server log and (outside production) returns it so the UI can surface it
 * honestly instead of pretending a message was delivered.
 */
const consoleTransport: MailTransport = {
  name: 'console',
  async send(message, actionUrl) {
    logger.info(
      { to: message.to, subject: message.subject, actionUrl: isProduction ? '[redacted]' : actionUrl },
      'Email not sent: EMAIL_TRANSPORT=console (development transport)',
    );
    return {
      delivered: false,
      transport: 'console',
      ...(actionUrl && !isProduction ? { previewUrl: actionUrl } : {}),
    };
  },
};

const resendTransport: MailTransport = {
  name: 'resend',
  async send(message) {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY ?? ''}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: env.EMAIL_FROM,
        to: [message.to],
        subject: message.subject,
        text: message.text,
        html: message.html,
      }),
    });

    if (!response.ok) {
      // Body may contain the provider's error detail; log status only.
      logger.error({ status: response.status, to: message.to }, 'Email provider rejected the message');
      return { delivered: false, transport: 'resend' };
    }

    return { delivered: true, transport: 'resend' };
  },
};

let cachedSmtpTransporter: ReturnType<typeof nodemailer.createTransport> | undefined;

function smtpTransporter(): ReturnType<typeof nodemailer.createTransport> {
  if (!cachedSmtpTransporter) {
    cachedSmtpTransporter = nodemailer.createTransport({
      host: env.SMTP_HOST,
      port: env.SMTP_PORT ?? (env.SMTP_SECURE ? 465 : 587),
      secure: env.SMTP_SECURE,
      auth: { user: env.SMTP_USER, pass: env.SMTP_PASS },
      // A hung relay must never pin a request forever.
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 20_000,
    });
  }
  return cachedSmtpTransporter;
}

/** Extracts the useful bits of a nodemailer failure without leaking creds. */
function smtpErrorDetail(error: unknown): Record<string, unknown> {
  if (!(error instanceof Error)) return { err: 'unknown smtp error' };
  const e = error as Error & { code?: string; responseCode?: number; response?: string; command?: string };
  return {
    err: e.message,
    code: e.code,
    responseCode: e.responseCode,
    response: e.response,
    command: e.command,
  };
}

/**
 * User-configured SMTP account (SMTP_HOST/PORT/USER/PASS in .env) - works with
 * Gmail app passwords, Outlook, or any provider relay. The transporter is
 * created once and reused so every send doesn't pay the TCP+TLS handshake.
 */
const smtpTransport: MailTransport = {
  name: 'smtp',
  async send(message) {
    try {
      await smtpTransporter().sendMail({
        from: env.EMAIL_FROM,
        to: message.to,
        subject: message.subject,
        text: message.text,
        html: message.html,
      });
      logger.info({ to: message.to, subject: message.subject }, 'Email delivered via SMTP');
      return { delivered: true, transport: 'smtp' };
    } catch (error) {
      logger.error({ ...smtpErrorDetail(error), to: message.to }, 'SMTP transport rejected the message');
      return { delivered: false, transport: 'smtp' };
    }
  },
};

export const mailer: MailTransport =
  env.EMAIL_TRANSPORT === 'resend'
    ? resendTransport
    : env.EMAIL_TRANSPORT === 'smtp'
      ? smtpTransport
      : consoleTransport;

/**
 * Startup sanity probe: logs which mail transport is active, and for SMTP
 * verifies the connection + credentials once so a bad config surfaces as a
 * loud boot-time error instead of silently eating every email later.
 * Never throws - a mail outage must not stop the API from booting.
 */
export async function verifyMailTransport(): Promise<void> {
  if (env.EMAIL_TRANSPORT === 'console') {
    logger.trace('Mail transport: console - emails are logged, never delivered');
    return;
  }

  if (env.EMAIL_TRANSPORT !== 'smtp') return;

  try {
    await smtpTransporter().verify();
    logger.trace(
      { host: env.SMTP_HOST, port: env.SMTP_PORT ?? (env.SMTP_SECURE ? 465 : 587) },
      'SMTP connection verified',
    );
  } catch (error) {
    logger.error(
      { ...smtpErrorDetail(error), host: env.SMTP_HOST, user: env.SMTP_USER },
      'SMTP verification failed - check SMTP_HOST/PORT/USER/PASS in .env. Emails will fail to send until fixed.',
    );
  }
}

/** User-controlled strings (name, email) go through this before touching HTML. */
function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Enterprise-grade white email layout. Table-based so it renders consistently
 * across Gmail/Outlook/Apple Mail; fluid up to 560px so it reads well on
 * phones; every string stays inline-styled (no <style> blocks some clients
 * strip).
 */
function layout(options: {
  title: string;
  body: string;
  actionUrl?: string;
  actionLabel?: string;
  code?: string;
  /** Small muted line right under the CTA/code, e.g. expiry details. */
  footnote?: string;
}): string {
  const { title, body, actionUrl, actionLabel, code, footnote } = options;
  const year = new Date().getFullYear();

  const codeBlock = code
    ? `<tr><td style="padding:4px 0 8px">
         <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto">
           <tr><td style="background:#f4f5fb;border:1px solid #e3e5f2;border-radius:12px;padding:14px 28px;font-family:'Courier New',Courier,monospace;font-size:32px;font-weight:700;letter-spacing:10px;color:#0f1222;text-align:center">${code}</td></tr>
         </table>
       </td></tr>`
    : '';

  const button = actionUrl
    ? `<tr><td style="padding:8px 0 4px">
         <a href="${actionUrl}" style="display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;font-size:14px;font-weight:600;padding:12px 24px;border-radius:10px">${actionLabel}</a>
       </td></tr>`
    : '';

  const footnoteRow = footnote
    ? `<tr><td style="font-size:12px;line-height:18px;color:#8b90a7;padding-top:18px">${footnote}</td></tr>`
    : '';

  return `<!doctype html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="x-apple-disable-message-reformatting">
<title>${title}</title>
</head>
<body style="margin:0;padding:0;background:#f6f7fb;font-family:'Segoe UI',Inter,-apple-system,BlinkMacSystemFont,Arial,sans-serif;color:#0f1222">
  <div style="display:none;max-height:0;overflow:hidden">${title}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f6f7fb;padding:28px 16px">
    <tr><td align="center">

      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px">
        <tr><td style="padding:0 4px 16px">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            <td style="width:26px;height:26px;background:#4f46e5;border-radius:7px;color:#fff;font-size:13px;font-weight:800;text-align:center;line-height:26px">V</td>
            <td style="padding-left:9px;font-size:15px;font-weight:700;color:#0f1222">Vaultory</td>
          </tr></table>
        </td></tr>

        <tr><td style="background:#ffffff;border:1px solid #e6e8f0;border-radius:16px;padding:30px 28px">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
            <tr><td style="font-size:21px;font-weight:700;line-height:28px;color:#0f1222;padding-bottom:10px">${title}</td></tr>
            <tr><td style="font-size:14px;line-height:22px;color:#4a4f68;padding-bottom:6px">${body}</td></tr>
            ${codeBlock}
            ${button}
            ${footnoteRow}
            <tr><td style="padding-top:22px"><hr style="border:none;border-top:1px solid #eceef5;margin:0"></td></tr>
            <tr><td style="font-size:12px;line-height:18px;color:#8b90a7;padding-top:16px">
              If you did not request this email, you can safely ignore it.
            </td></tr>
          </table>
        </td></tr>

        <tr><td style="padding:16px 4px 0;font-size:11px;line-height:17px;color:#9ba0b5;text-align:center">
          Vaultory - a personal, encrypted vault.<br>
          This is an automated message, please do not reply.<br>
          &copy; ${year} Vaultory
        </td></tr>
      </table>

    </td></tr>
  </table>
</body></html>`;
}

export function passwordResetEmail(to: string, resetUrl: string): { message: MailMessage; actionUrl: string } {
  return {
    actionUrl: resetUrl,
    message: {
      to,
      subject: 'Reset your Vaultory password',
      text: [
        'We received a request to reset your Vaultory password.',
        '',
        'Use the link below to choose a new password:',
        resetUrl,
        '',
        'This link expires in 10 minutes and can be used once.',
        'If it has expired, request a fresh email from the sign-in page.',
        '',
        'Your existing vault is preserved - the same vault key is re-wrapped to',
        'your new password, so every saved item keeps working.',
        '',
        'If you did not request this, ignore this email.',
      ].join('\n'),
      html: layout({
        title: 'Reset your password',
        body: `We received a request to reset the password for your Vaultory account.
               Use the button below to choose a new one.<br><br>
               Your existing vault is preserved: the same vault key is re-wrapped to your
               new password, so every saved item keeps working.`,
        actionUrl: resetUrl,
        actionLabel: 'Choose a new password',
        footnote:
          'This link is valid for <strong>10 minutes</strong> and can only be used once. ' +
          'If it has expired, request a fresh email from the sign-in page.',
      }),
    },
  };
}

export function verifyEmailEmail(
  to: string,
  verifyUrl: string,
  code: string,
): { message: MailMessage; actionUrl: string } {
  return {
    actionUrl: verifyUrl,
    message: {
      to,
      subject: `${code} is your Vaultory verification code`,
      text: [
        'Confirm your email address to finish setting up Vaultory.',
        '',
        `Your verification code: ${code}`,
        '',
        `Or use this link: ${verifyUrl}`,
        '',
        'The code and link expire in 24 hours.',
      ].join('\n'),
      html: layout({
        title: 'Confirm your email address',
        body: `Enter this code in Vaultory to verify <strong>${escapeHtml(to)}</strong>, or use the button below.`,
        code,
        actionUrl: verifyUrl,
        actionLabel: 'Confirm email',
        footnote: 'The code and link expire in <strong>24 hours</strong>.',
      }),
    },
  };
}

export function welcomeEmail(to: string, name: string | null): { message: MailMessage } {
  const displayName = name?.trim() || 'there';
  return {
    message: {
      to,
      subject: 'Welcome to Vaultory',
      text: [
        `Hi ${displayName},`,
        '',
        'Welcome to Vaultory - your private vault for passwords, API keys, notes and files.',
        '',
        'Everything you save is encrypted in your browser with AES-256-GCM before it',
        'reaches our servers, so only you can ever read your secrets.',
        '',
        'A few things worth doing first:',
        '- Turn on two-factor authentication from the Security page',
        '- Organise entries into folders (they can nest three levels deep)',
        '- Export an encrypted backup once your vault starts filling up',
        '',
        `Get started: ${env.APP_URL}`,
        '',
        'The Vaultory team',
      ].join('\n'),
      html: layout({
        title: `Welcome to Vaultory, ${escapeHtml(displayName)}`,
        body: `Your private vault for passwords, API keys, notes and files is ready.
               Everything you save is encrypted in your browser with AES-256-GCM before it
               reaches our servers - only you can ever read your secrets.<br><br>
               A few things worth doing first:<br>
               &bull;&nbsp; Turn on two-factor authentication from the Security page<br>
               &bull;&nbsp; Organise entries into folders - they can nest three levels deep<br>
               &bull;&nbsp; Export an encrypted backup once your vault starts filling up`,
        actionUrl: env.APP_URL,
        actionLabel: 'Open your vault',
      }),
    },
  };
}
