-- CreateTable
CREATE TABLE `IAMScope` (
    `id` VARCHAR(191) NOT NULL,
    `ownerId` VARCHAR(191) NOT NULL,
    `path` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `IAMResource` (
    `id` VARCHAR(191) NOT NULL,
    `scopeId` VARCHAR(191) NOT NULL,
    `resourceId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `IAMResourceGrant` (
    `id` VARCHAR(191) NOT NULL,
    `resourceId` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `IAMScope` ADD CONSTRAINT `IAMScope_ownerId_fkey` FOREIGN KEY (`ownerId`) REFERENCES `OAuthClient`(`clientId`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `IAMResource` ADD CONSTRAINT `IAMResource_scopeId_fkey` FOREIGN KEY (`scopeId`) REFERENCES `IAMScope`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `IAMResourceGrant` ADD CONSTRAINT `IAMResourceGrant_resourceId_fkey` FOREIGN KEY (`resourceId`) REFERENCES `IAMResource`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `IAMResourceGrant` ADD CONSTRAINT `IAMResourceGrant_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
