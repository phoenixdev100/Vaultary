-- Nested folders: a folder can live inside another folder. Deleting a parent
-- lifts its children to the deleted folder's parent (SetNull).
ALTER TABLE "Folder" ADD COLUMN "parentId" TEXT;
ALTER TABLE "Folder" ADD CONSTRAINT "Folder_parentId_fkey" FOREIGN KEY ("parentId") REFERENCES "Folder"("id") ON DELETE SET NULL ON UPDATE CASCADE;
CREATE INDEX "Folder_parentId_idx" ON "Folder"("parentId");
