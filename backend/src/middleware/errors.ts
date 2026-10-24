import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError, type ZodIssue } from 'zod';
import { logger } from '../config/logger.js';
import { Prisma } from '../generated/prisma/client.js';
import { ApiError } from '../utils/http.js';

/** Field names whose validation messages must never be echoed back. */
const SENSITIVE_PATHS = new Set([
  'ciphertext',
  'nonce',
  'authVerifier',
  'currentAuthVerifier',
  'newAuthVerifier',
  'wrappedVaultKey',
  'newWrappedVaultKey',
  'token',
]);

function describeIssue(issue: ZodIssue): { field: string; message: string } {
  const field = issue.path.map(String).join('.') || '(body)';
  const leaf = issue.path.length > 0 ? String(issue.path[issue.path.length - 1]) : '';
  if (SENSITIVE_PATHS.has(leaf)) return { field, message: 'Invalid value' };
  return { field, message: issue.message };
}

export const notFoundHandler: RequestHandler = (_req, res) => {
  res.status(404).json({ error: { code: 'not_found', message: 'Endpoint not found' } });
};

export const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  if (res.headersSent) {
    next(err);
    return;
  }

  if (err instanceof ZodError) {
    res.status(400).json({
      error: {
        code: 'validation_error',
        message: 'Some fields need attention',
        details: err.issues.map(describeIssue),
      },
    });
    return;
  }

  if (err instanceof ApiError) {
    if (err.headers) {
      for (const [key, value] of Object.entries(err.headers)) res.setHeader(key, value);
    }
    res.status(err.status).json({
      error: { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) },
    });
    return;
  }

  if (err instanceof SyntaxError && 'body' in err) {
    res.status(400).json({ error: { code: 'invalid_json', message: 'Request body is not valid JSON' } });
    return;
  }

  if (typeof err === 'object' && err !== null && (err as { type?: string }).type === 'entity.too.large') {
    res.status(413).json({ error: { code: 'payload_too_large', message: 'Request body is too large' } });
    return;
  }

  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    if (err.code === 'P2002') {
      res.status(409).json({ error: { code: 'conflict', message: 'That value is already in use' } });
      return;
    }
    if (err.code === 'P2025') {
      res.status(404).json({ error: { code: 'not_found', message: 'Resource not found' } });
      return;
    }
    if (err.code === 'P2003') {
      res.status(400).json({ error: { code: 'bad_request', message: 'Related record does not exist' } });
      return;
    }
  }

  // Unknown failure: log the detail, return nothing useful to the caller.
  logger.error(
    { err, requestId: req.requestId, method: req.method, path: req.originalUrl },
    'Unhandled error while processing request',
  );
  res.status(500).json({
    error: {
      code: 'internal_error',
      message: 'Something went wrong on our side',
      ...(req.requestId ? { requestId: req.requestId } : {}),
    },
  });
};
