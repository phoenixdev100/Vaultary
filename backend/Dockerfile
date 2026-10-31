# syntax=docker/dockerfile:1

# ── deps: install + generate the Prisma client (postinstall) ─────────
FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY prisma ./prisma
COPY prisma.config.ts ./
RUN npm ci

# ── build: compile TypeScript (generated client lands in dist/) ──────
FROM deps AS build
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ── prod-deps: runtime node_modules only ─────────────────────────────
FROM node:24-alpine AS prod-deps
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

# ── runtime: non-root, smallest possible surface ─────────────────────
FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S vaultory && adduser -S vaultory -G vaultory
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
# prisma CLI + engines + schema so the entrypoint can `migrate deploy` before
# the server boots - keeps one backend image instead of a separate migrate one.
COPY --from=deps /app/node_modules/prisma ./node_modules/prisma
COPY --from=deps /app/node_modules/@prisma ./node_modules/@prisma
COPY --from=deps /app/node_modules/.bin ./node_modules/.bin
COPY prisma ./prisma
COPY prisma.config.ts package.json ./
USER vaultory
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# Apply pending migrations, then boot. `migrate deploy` is idempotent so this
# doubles as the one-shot migrate service - one backend image, no extra pull.
ENTRYPOINT ["sh", "-c", "npx prisma migrate deploy && exec node dist/src/server.js"]
