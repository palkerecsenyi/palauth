-- CreateTable
CREATE TABLE `OAuthToken` (
    `id` VARCHAR(191) NOT NULL,
    `type` ENUM('Access', 'Refresh') NOT NULL,
    `value` VARCHAR(191) NOT NULL,
    `issued` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `expires` DATETIME(3) NOT NULL,
    `fromCode` VARCHAR(191) NULL,
    `userId` VARCHAR(191) NOT NULL,
    `clientId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `OAuthTokenScope` (
    `tokenId` VARCHAR(191) NOT NULL,
    `scope` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`tokenId`, `scope`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `OAuthToken` ADD CONSTRAINT `OAuthToken_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `OAuthToken` ADD CONSTRAINT `OAuthToken_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `OAuthClient`(`clientId`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `OAuthTokenScope` ADD CONSTRAINT `OAuthTokenScope_tokenId_fkey` FOREIGN KEY (`tokenId`) REFERENCES `OAuthToken`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
