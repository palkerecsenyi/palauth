/*
  Warnings:

  - Added the required column `type` to the `SecondAuthenticationFactor` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `SecondAuthenticationFactor` ADD COLUMN `type` ENUM('SecurityKey', 'TOTP') NOT NULL;
