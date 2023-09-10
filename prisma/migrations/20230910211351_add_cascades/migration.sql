-- DropForeignKey
ALTER TABLE `OAuthClientRedirectURI` DROP FOREIGN KEY `OAuthClientRedirectURI_clientId_fkey`;

-- DropForeignKey
ALTER TABLE `OAuthToken` DROP FOREIGN KEY `OAuthToken_clientId_fkey`;

-- DropForeignKey
ALTER TABLE `OAuthToken` DROP FOREIGN KEY `OAuthToken_userId_fkey`;

-- DropForeignKey
ALTER TABLE `OAuthTokenScope` DROP FOREIGN KEY `OAuthTokenScope_tokenId_fkey`;

-- DropForeignKey
ALTER TABLE `UserOAuthGrant` DROP FOREIGN KEY `UserOAuthGrant_clientId_fkey`;

-- AddForeignKey
ALTER TABLE `OAuthClientRedirectURI` ADD CONSTRAINT `OAuthClientRedirectURI_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `OAuthClient`(`clientId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `UserOAuthGrant` ADD CONSTRAINT `UserOAuthGrant_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `OAuthClient`(`clientId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `OAuthToken` ADD CONSTRAINT `OAuthToken_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `OAuthToken` ADD CONSTRAINT `OAuthToken_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `OAuthClient`(`clientId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `OAuthTokenScope` ADD CONSTRAINT `OAuthTokenScope_tokenId_fkey` FOREIGN KEY (`tokenId`) REFERENCES `OAuthToken`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
