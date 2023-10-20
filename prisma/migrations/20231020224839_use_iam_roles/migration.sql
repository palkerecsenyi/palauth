/*
  Warnings:

  - You are about to drop the `IAMResource` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `IAMResourceGrant` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `IAMScope` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE `IAMResource` DROP FOREIGN KEY `IAMResource_scopeId_fkey`;

-- DropForeignKey
ALTER TABLE `IAMResourceGrant` DROP FOREIGN KEY `IAMResourceGrant_resourceId_fkey`;

-- DropForeignKey
ALTER TABLE `IAMResourceGrant` DROP FOREIGN KEY `IAMResourceGrant_userId_fkey`;

-- DropForeignKey
ALTER TABLE `IAMScope` DROP FOREIGN KEY `IAMScope_ownerId_fkey`;

-- DropTable
DROP TABLE `IAMResource`;

-- DropTable
DROP TABLE `IAMResourceGrant`;

-- DropTable
DROP TABLE `IAMScope`;

-- CreateTable
CREATE TABLE `IAMPermission` (
    `id` VARCHAR(191) NOT NULL,
    `ownerId` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `IAMRole` (
    `id` VARCHAR(191) NOT NULL,
    `ownerId` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `IAMRoleAssignment` (
    `userId` VARCHAR(191) NOT NULL,
    `roleId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`userId`, `roleId`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `_IAMPermissionToIAMRole` (
    `A` VARCHAR(191) NOT NULL,
    `B` VARCHAR(191) NOT NULL,

    UNIQUE INDEX `_IAMPermissionToIAMRole_AB_unique`(`A`, `B`),
    INDEX `_IAMPermissionToIAMRole_B_index`(`B`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `_PermissionRequirementTree` (
    `A` VARCHAR(191) NOT NULL,
    `B` VARCHAR(191) NOT NULL,

    UNIQUE INDEX `_PermissionRequirementTree_AB_unique`(`A`, `B`),
    INDEX `_PermissionRequirementTree_B_index`(`B`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `IAMPermission` ADD CONSTRAINT `IAMPermission_ownerId_fkey` FOREIGN KEY (`ownerId`) REFERENCES `OAuthClient`(`clientId`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `IAMRole` ADD CONSTRAINT `IAMRole_ownerId_fkey` FOREIGN KEY (`ownerId`) REFERENCES `OAuthClient`(`clientId`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `IAMRoleAssignment` ADD CONSTRAINT `IAMRoleAssignment_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `IAMRoleAssignment` ADD CONSTRAINT `IAMRoleAssignment_roleId_fkey` FOREIGN KEY (`roleId`) REFERENCES `IAMRole`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `_IAMPermissionToIAMRole` ADD CONSTRAINT `_IAMPermissionToIAMRole_A_fkey` FOREIGN KEY (`A`) REFERENCES `IAMPermission`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `_IAMPermissionToIAMRole` ADD CONSTRAINT `_IAMPermissionToIAMRole_B_fkey` FOREIGN KEY (`B`) REFERENCES `IAMRole`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `_PermissionRequirementTree` ADD CONSTRAINT `_PermissionRequirementTree_A_fkey` FOREIGN KEY (`A`) REFERENCES `IAMPermission`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `_PermissionRequirementTree` ADD CONSTRAINT `_PermissionRequirementTree_B_fkey` FOREIGN KEY (`B`) REFERENCES `IAMPermission`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
