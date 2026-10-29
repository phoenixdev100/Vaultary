-- Add coarse geo country to sessions for the sign-in map.
ALTER TABLE "Session" ADD COLUMN "country" TEXT;
