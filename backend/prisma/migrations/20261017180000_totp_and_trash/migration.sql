-- Account TOTP 2FA + vault trash (soft-delete).
ALTER TYPE "ActivityType" ADD VALUE IF NOT EXISTS 'SECRET_TRASHED';
ALTER TYPE "ActivityType" ADD VALUE IF NOT EXISTS 'SECRET_PURGED';
ALTER TYPE "ActivityType" ADD VALUE IF NOT EXISTS 'TOTP_ENABLED';
ALTER TYPE "ActivityType" ADD VALUE IF NOT EXISTS 'TOTP_DISABLED';

ALTER TABLE "User"
  ADD COLUMN "totpSecret" TEXT,
  ADD COLUMN "totpEnabled" BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE "Secret" ADD COLUMN "deletedAt" TIMESTAMP(3);
CREATE INDEX "Secret_userId_deletedAt_idx" ON "Secret"("userId", "deletedAt");
