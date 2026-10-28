-- The same vault key, ECDH-wrapped to the server escrow key so that an
-- email-verified password reset can recover it without a recovery phrase.
ALTER TABLE "User" ADD COLUMN "serverWrappedVaultKey" TEXT;
