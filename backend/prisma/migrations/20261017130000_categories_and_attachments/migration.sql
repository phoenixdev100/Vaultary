-- New secret categories covering cloud, env files, certs, payments, email,
-- identity, mobile signing, crypto and personal credentials.
ALTER TYPE "SecretCategory" ADD VALUE 'CLOUD';
ALTER TYPE "SecretCategory" ADD VALUE 'ENV_VARS';
ALTER TYPE "SecretCategory" ADD VALUE 'PRIVATE_KEY';
ALTER TYPE "SecretCategory" ADD VALUE 'PAYMENT';
ALTER TYPE "SecretCategory" ADD VALUE 'EMAIL_SERVICE';
ALTER TYPE "SecretCategory" ADD VALUE 'IDENTITY';
ALTER TYPE "SecretCategory" ADD VALUE 'MOBILE';
ALTER TYPE "SecretCategory" ADD VALUE 'CRYPTO';
ALTER TYPE "SecretCategory" ADD VALUE 'PERSONAL';

ALTER TYPE "ActivityType" ADD VALUE 'ATTACHMENT_UPLOADED';
ALTER TYPE "ActivityType" ADD VALUE 'ATTACHMENT_DELETED';

-- Encrypted file attachments on secrets.
CREATE TABLE "Attachment" (
  "id" TEXT NOT NULL,
  "userId" TEXT NOT NULL,
  "secretId" TEXT NOT NULL,
  "fileName" TEXT NOT NULL,
  "mimeType" TEXT,
  "size" INTEGER NOT NULL,
  "encVersion" INTEGER NOT NULL DEFAULT 1,
  "keyVersion" INTEGER NOT NULL DEFAULT 1,
  "nonce" TEXT NOT NULL,
  "ciphertext" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "Attachment_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "Attachment_secretId_idx" ON "Attachment"("secretId");
CREATE INDEX "Attachment_userId_idx" ON "Attachment"("userId");
ALTER TABLE "Attachment" ADD CONSTRAINT "Attachment_secretId_fkey"
  FOREIGN KEY ("secretId") REFERENCES "Secret"("id") ON DELETE CASCADE ON UPDATE CASCADE;
