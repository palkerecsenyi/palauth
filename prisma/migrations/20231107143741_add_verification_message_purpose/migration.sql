/*
  Warnings:

  - Added the required column `purpose` to the `EmailVerification` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `EmailVerification` ADD COLUMN `purpose` ENUM('VerifyEmail', 'PasswordReset') NOT NULL;
