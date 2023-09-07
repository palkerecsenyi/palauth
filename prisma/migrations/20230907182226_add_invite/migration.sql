/*
  Warnings:

  - You are about to drop the column `passwordSalt` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE `User` DROP COLUMN `passwordSalt`;

-- CreateTable
CREATE TABLE `Invite` (
    `token` VARCHAR(191) NOT NULL,
    `expires` DATETIME(3) NULL,
    `singleUse` BOOLEAN NOT NULL,

    PRIMARY KEY (`token`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
