/** Error with an HTTP status and a stable machine-readable code. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: unknown;
  readonly headers?: Record<string, string>;

  constructor(
    status: number,
    code: string,
    message: string,
    options?: { details?: unknown; headers?: Record<string, string> },
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = options?.details;
    this.headers = options?.headers;
  }

  static badRequest(message: string, details?: unknown): ApiError {
    return new ApiError(400, 'bad_request', message, { details });
  }

  static unauthorized(message = 'Authentication required'): ApiError {
    return new ApiError(401, 'unauthorized', message);
  }

  static forbidden(message = 'You do not have access to this resource'): ApiError {
    return new ApiError(403, 'forbidden', message);
  }

  static notFound(message = 'Resource not found'): ApiError {
    return new ApiError(404, 'not_found', message);
  }

  static conflict(message: string): ApiError {
    return new ApiError(409, 'conflict', message);
  }

  static payloadTooLarge(message: string): ApiError {
    return new ApiError(413, 'payload_too_large', message);
  }

  static tooManyRequests(message: string, retryAfterSeconds: number): ApiError {
    return new ApiError(429, 'rate_limited', message, {
      headers: { 'Retry-After': String(Math.max(1, retryAfterSeconds)) },
    });
  }
}
