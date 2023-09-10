/*
  Warnings:

  - Added the required column `name` to the `OAuthClient` table without a default value. This is not possible if the table is not empty.
  - Added the required column `usageDescription` to the `OAuthClient` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `OAuthClient` ADD COLUMN `name` VARCHAR(191) NOT NULL,
    ADD COLUMN `usageDescription` VARCHAR(191) NOT NULL;
