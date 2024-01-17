/*
  Warnings:

  - A unique constraint covering the columns `[ownerId,name]` on the table `IAMPermission` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[ownerId,name]` on the table `IAMRole` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX `IAMPermission_ownerId_name_key` ON `IAMPermission`(`ownerId`, `name`);

-- CreateIndex
CREATE UNIQUE INDEX `IAMRole_ownerId_name_key` ON `IAMRole`(`ownerId`, `name`);
