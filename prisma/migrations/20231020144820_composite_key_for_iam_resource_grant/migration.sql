/*
  Warnings:

  - The primary key for the `IAMResourceGrant` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `id` on the `IAMResourceGrant` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[scopeId,resourceId]` on the table `IAMResource` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE `IAMResourceGrant` DROP PRIMARY KEY,
    DROP COLUMN `id`,
    ADD PRIMARY KEY (`resourceId`, `userId`);

-- CreateIndex
CREATE UNIQUE INDEX `IAMResource_scopeId_resourceId_key` ON `IAMResource`(`scopeId`, `resourceId`);
