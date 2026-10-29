-- CreateEnum
CREATE TYPE "ShareStatus" AS ENUM ('PENDING', 'ACCEPTED');

-- CreateEnum
CREATE TYPE "EmergencyStatus" AS ENUM ('PENDING', 'WAITING', 'APPROVED', 'CANCELLED');

-- AlterEnum
-- This migration adds more than one value to an enum.
-- With PostgreSQL versions 11 and earlier, this is not possible
-- in a single migration. This can be worked around by creating
-- multiple migrations, each migration adding only one value to
-- the enum.

ALTER TYPE "ActivityType" ADD VALUE 'SHARE_SENT';
ALTER TYPE "ActivityType" ADD VALUE 'SHARE_ACCEPTED';
ALTER TYPE "ActivityType" ADD VALUE 'SHARE_REVOKED';
ALTER TYPE "ActivityType" ADD VALUE 'EMERGENCY_GRANTED';
ALTER TYPE "ActivityType" ADD VALUE 'EMERGENCY_REQUESTED';
ALTER TYPE "ActivityType" ADD VALUE 'EMERGENCY_APPROVED';
ALTER TYPE "ActivityType" ADD VALUE 'EMERGENCY_CANCELLED';
ALTER TYPE "ActivityType" ADD VALUE 'EMERGENCY_USED';

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "sharePrivateKeyWrapped" JSONB,
ADD COLUMN     "sharePublicKey" TEXT;

-- CreateTable
CREATE TABLE "Share" (
    "id" TEXT NOT NULL,
    "senderId" TEXT NOT NULL,
    "recipientId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "category" "SecretCategory" NOT NULL,
    "senderPublicKey" TEXT NOT NULL,
    "nonce" TEXT NOT NULL,
    "ciphertext" TEXT NOT NULL,
    "status" "ShareStatus" NOT NULL DEFAULT 'PENDING',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "Share_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EmergencyGrant" (
    "id" TEXT NOT NULL,
    "grantorId" TEXT NOT NULL,
    "granteeId" TEXT NOT NULL,
    "status" "EmergencyStatus" NOT NULL DEFAULT 'PENDING',
    "waitDays" INTEGER NOT NULL DEFAULT 7,
    "requestedAt" TIMESTAMP(3),
    "waitUntil" TIMESTAMP(3),
    "approvedAt" TIMESTAMP(3),
    "handoverSenderPublicKey" TEXT,
    "handoverNonce" TEXT,
    "handoverCiphertext" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EmergencyGrant_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Share_recipientId_status_idx" ON "Share"("recipientId", "status");

-- CreateIndex
CREATE INDEX "Share_senderId_idx" ON "Share"("senderId");

-- CreateIndex
CREATE INDEX "EmergencyGrant_granteeId_status_idx" ON "EmergencyGrant"("granteeId", "status");

-- CreateIndex
CREATE INDEX "EmergencyGrant_grantorId_idx" ON "EmergencyGrant"("grantorId");

-- AddForeignKey
ALTER TABLE "Share" ADD CONSTRAINT "Share_senderId_fkey" FOREIGN KEY ("senderId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Share" ADD CONSTRAINT "Share_recipientId_fkey" FOREIGN KEY ("recipientId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmergencyGrant" ADD CONSTRAINT "EmergencyGrant_grantorId_fkey" FOREIGN KEY ("grantorId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmergencyGrant" ADD CONSTRAINT "EmergencyGrant_granteeId_fkey" FOREIGN KEY ("granteeId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
