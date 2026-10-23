# Contributing to Vaultory

Thanks for your interest. Vaultory is a personal secrets manager - correctness and privacy beat features, so please keep that bar in mind.

## Ground rules

- **No plaintext secrets.** Secret values must be encrypted in the browser before they touch the network. Never log, index, or return decrypted payloads server-side.
- **No new secrets in commits.** `.env`, keys, tokens stay local - `.env.example` files hold placeholders only.
- **Security semantics are load-bearing.** Ownership checks in queries, CSRF/origin guards, HMAC-hashed tokens, generic enumeration-safe responses - don't weaken them to make a test pass.
- Keep the two themes (light default, dark) and the responsive layout intact.

## Development setup

```bash
cd backend && cp .env.example .env   # fill DATABASE_URL, SESSION_SECRET, VAULT_WRAP_SECRET
npm install && npx prisma migrate deploy && npm run dev

cd frontend && npm install && npm run dev
```

## Before opening a PR

| Check           | Command                                              |
| --------------- | ---------------------------------------------------- |
| Backend tests   | `cd backend && npm test`                             |
| Backend checks  | `npm run typecheck && npm run lint && npm run build` |
| Frontend tests  | `cd frontend && npm test`                            |
| Frontend checks | `npm run typecheck && npm run lint && npm run build` |
| E2E (optional)  | `cd frontend && npm run e2e`                         |

- Follow existing code style - TypeScript strict, Tailwind utility classes, `cn()` for conditionals.
- Adding a route? Zod-validate the body, scope queries by `userId`, add a test.
- Schema changes: `npx prisma migrate dev` and commit the generated migration folder.

## Reporting security issues

Please do **not** open public issues for vulnerabilities. Report privately to the maintainer via GitHub ([@phoenixdev100](https://github.com/phoenixdev100)) and allow time for a fix before disclosure.
