/*
  Warnings:

  - Added the required column `adminId` to the `OAuthClient` table without a default value. This is not possible if the table is not empty.
  - Added the required column `uri` to the `OAuthClientRedirectURI` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `OAuthClient` ADD COLUMN `adminId` VARCHAR(191) NOT NULL;

-- AlterTable
ALTER TABLE `OAuthClientRedirectURI` ADD COLUMN `uri` VARCHAR(191) NOT NULL;

-- AddForeignKey
ALTER TABLE `OAuthClient` ADD CONSTRAINT `OAuthClient_adminId_fkey` FOREIGN KEY (`adminId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
