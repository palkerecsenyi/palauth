-- DropForeignKey
ALTER TABLE `EmailVerification` DROP FOREIGN KEY `EmailVerification_userId_fkey`;

-- AddForeignKey
ALTER TABLE `EmailVerification` ADD CONSTRAINT `EmailVerification_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
