-- Personal workspaces ("organizations"): every folder/secret/attachment is
-- scoped to exactly one workspace so data from one workspace can never leak
-- into another workspace's listings. Existing rows are backfilled into a
-- per-user "Personal" workspace (isDefault), which also catches requests from
-- older clients that do not send an X-Workspace-Id header.

CREATE TABLE "Workspace" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "color" TEXT,
    "isDefault" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Workspace_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "Folder" ADD COLUMN "workspaceId" TEXT;
ALTER TABLE "Secret" ADD COLUMN "workspaceId" TEXT;
ALTER TABLE "Attachment" ADD COLUMN "workspaceId" TEXT;

-- Backfill: one Personal workspace per existing user, then point every row at
-- its owner's workspace. Runs inside the migration transaction, so a partially
-- migrated database can never observe NULLs.
INSERT INTO "Workspace" ("id", "userId", "name", "isDefault", "createdAt", "updatedAt")
SELECT gen_random_uuid()::text, "id", 'Personal', true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM "User";

UPDATE "Folder" f SET "workspaceId" = w."id"
FROM "Workspace" w WHERE w."userId" = f."userId" AND w."isDefault" = true;

UPDATE "Secret" s SET "workspaceId" = w."id"
FROM "Workspace" w WHERE w."userId" = s."userId" AND w."isDefault" = true;

UPDATE "Attachment" a SET "workspaceId" = w."id"
FROM "Workspace" w WHERE w."userId" = a."userId" AND w."isDefault" = true;

ALTER TABLE "Folder" ALTER COLUMN "workspaceId" SET NOT NULL;
ALTER TABLE "Secret" ALTER COLUMN "workspaceId" SET NOT NULL;
ALTER TABLE "Attachment" ALTER COLUMN "workspaceId" SET NOT NULL;

ALTER TABLE "Folder" ADD CONSTRAINT "Folder_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Secret" ADD CONSTRAINT "Secret_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Attachment" ADD CONSTRAINT "Attachment_workspaceId_fkey" FOREIGN KEY ("workspaceId") REFERENCES "Workspace"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "Workspace" ADD CONSTRAINT "Workspace_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Folder names were unique per user; they are now unique per workspace so the
-- same name can exist in different orgs.
DROP INDEX "Folder_userId_name_key";
CREATE UNIQUE INDEX "Folder_workspaceId_name_key" ON "Folder"("workspaceId", "name");
CREATE UNIQUE INDEX "Workspace_userId_name_key" ON "Workspace"("userId", "name");

CREATE INDEX "Workspace_userId_idx" ON "Workspace"("userId");
CREATE INDEX "Folder_workspaceId_idx" ON "Folder"("workspaceId");
CREATE INDEX "Secret_workspaceId_idx" ON "Secret"("workspaceId");
CREATE INDEX "Secret_workspaceId_updatedAt_idx" ON "Secret"("workspaceId", "updatedAt" DESC);
CREATE INDEX "Secret_workspaceId_category_idx" ON "Secret"("workspaceId", "category");
CREATE INDEX "Secret_workspaceId_folderId_idx" ON "Secret"("workspaceId", "folderId");
CREATE INDEX "Secret_workspaceId_isFavorite_idx" ON "Secret"("workspaceId", "isFavorite");
CREATE INDEX "Secret_workspaceId_deletedAt_idx" ON "Secret"("workspaceId", "deletedAt");
CREATE INDEX "Attachment_workspaceId_idx" ON "Attachment"("workspaceId");

ALTER TYPE "ActivityType" ADD VALUE 'WORKSPACE_CREATED';
ALTER TYPE "ActivityType" ADD VALUE 'WORKSPACE_RENAMED';
ALTER TYPE "ActivityType" ADD VALUE 'WORKSPACE_DELETED';
