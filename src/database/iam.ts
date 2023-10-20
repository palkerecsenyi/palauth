import { TransactionType } from "../types/prisma.js";
import { DBClient } from "./client.js";
import { IAMScope } from "./generated-models/index.js";

export interface IAMResourceIdentifier {
    scopePath: string
    resourceId: string
}

export type IAMResourceUserIdentifier = IAMResourceIdentifier & {
    userId: string
}

export default class IAMController {
    private clientId: string
    private scopes: IAMScope[]
    private tx: TransactionType
    private constructor(clientId: string, scopes: IAMScope[], tx: TransactionType) {
        this.clientId = clientId
        this.scopes = scopes
        this.tx = tx
    }

    static async forOAuthClient(clientId: string, tx: TransactionType = DBClient.getClient()) {
        const scopes = await tx.iAMScope.findMany({
            where: {
                ownerId: clientId,
            },
        })
        return new IAMController(clientId, scopes, tx)
    }

    private static validateScopePath(scopePath: string) {
        if (!scopePath.startsWith("/")) {
            throw new TypeError("Scope path must start with /")
        }
    }

    private findScope(scopePath: string) {
        IAMController.validateScopePath(scopePath)
        return this.scopes.find(s => {
            return s.path.startsWith(scopePath)
        })
    }

    private findResource(scopeId: string, resourceId: string) {
        return this.tx.iAMResource.findFirst({
            where: {
                scopeId: scopeId,
                resourceId: resourceId,
            },
            include: {
                grants: true,
            }
        })
    }

    private findPath(scopePath: string, resourceId: string) {
        const matchingScope = this.findScope(scopePath)
        if (!matchingScope) return undefined

        return this.findResource(matchingScope.id, resourceId)
    }

    async checkResource(request: IAMResourceUserIdentifier) {
        const resource = await this.findPath(request.scopePath, request.resourceId)
        if (!resource) return false

        const matchingGrant = resource.grants.find(g => {
            return g.userId === request.userId
        })
        return matchingGrant !== undefined
    }

    async registerResource(resource: IAMResourceIdentifier) {
        const matchingScope = this.findScope(resource.scopePath)
        if (!matchingScope) throw new Error("Scope not found")

        await this.tx.iAMResource.upsert({
            where: {
                scopeId_resourceId: {
                    scopeId: matchingScope.id,
                    resourceId: resource.resourceId,
                }
            },
            update: {},
            create: {
                scopeId: matchingScope.id,
                resourceId: resource.resourceId,
            }
        })
    }

    async deleteResource({scopePath, resourceId}: IAMResourceIdentifier) {
        const resource = await this.findPath(scopePath, resourceId)
        if (!resource) throw new Error("Resource not found")

        await this.tx.iAMResource.delete({
            where: {
                id: resource.id,
            }
        })
    }

    async grant(
        {scopePath, resourceId, userId}: IAMResourceUserIdentifier,
        action: "grant" | "delete"
    ) {
        const alreadyGranted = await this.checkResource({
            scopePath, resourceId, userId
        })
        if (action === "grant" && alreadyGranted) {
            return
        } else if (action === "delete" && !alreadyGranted) {
            throw new Error("Access not granted")
        }

        const resource = await this.findPath(scopePath, resourceId)
        if (!resource) throw new Error("Resource not found")

        if (action === "grant") {
            await this.tx.iAMResourceGrant.create({
                data: {
                    resourceId: resource.id,
                    userId,
                }
            })
        } else if (action === "delete") {
            await this.tx.iAMResourceGrant.delete({
                where: {
                    resourceId_userId: {
                        resourceId: resource.id,
                        userId,
                    }
                }
            })
        }
    }
}
