-- AlterTable
ALTER TABLE `SecondAuthenticationFactor` ADD COLUMN `keyCounter` INTEGER NULL,
    ADD COLUMN `keyPublicKey` VARCHAR(191) NULL;
