-- CreateTable
CREATE TABLE `OAuthClient` (
    `clientId` VARCHAR(191) NOT NULL,
    `clientSecretHash` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`clientId`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `OAuthClientRedirectURI` (
    `id` VARCHAR(191) NOT NULL,
    `clientId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `OAuthClientRedirectURI` ADD CONSTRAINT `OAuthClientRedirectURI_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `OAuthClient`(`clientId`) ON DELETE RESTRICT ON UPDATE CASCADE;
