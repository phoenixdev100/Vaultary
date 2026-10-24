import type { Session, User } from '../generated/prisma/client.js';

declare global {
  namespace Express {
    interface Request {
      /** Populated by `requireAuth`. Server-side source of truth for ownership. */
      auth?: {
        user: User;
        session: Session;
      };
      /** True when auth came via Authorization: Bearer (extension clients). */
      bearerAuth?: boolean;
      /** Stable id attached to every request and echoed in 500 responses. */
      requestId?: string;
    }
  }
}

export {};
