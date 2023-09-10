-- CreateTable
CREATE TABLE `UserOAuthGrant` (
    `id` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,
    `clientId` VARCHAR(191) NOT NULL,
    `scope` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `UserOAuthGrant` ADD CONSTRAINT `UserOAuthGrant_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `UserOAuthGrant` ADD CONSTRAINT `UserOAuthGrant_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `OAuthClient`(`clientId`) ON DELETE RESTRICT ON UPDATE CASCADE;
