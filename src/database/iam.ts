import { TransactionType } from "../types/prisma.js";
import { DBClient } from "./client.js";
import { IAMScope } from "./generated-models/index.js";

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

    async checkResource(request: {
        userId: string,
        scopePath: string,
        resourceId: string,
    }) {
        const matchingScope = this.findScope(request.scopePath)
        if (!matchingScope) return false

        const resourceInScope = await this.findResource(matchingScope.id, request.resourceId)
        if (!resourceInScope) {
            return false
        }

        const matchingGrant = resourceInScope.grants.find(g => {
            return g.userId === request.userId
        })
        return matchingGrant !== undefined
    }

    async registerResource(resource: {
        scopePath: string,
        resourceId: string,
    }) {
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
}
