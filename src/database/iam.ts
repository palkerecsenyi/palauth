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

    async checkResource(request: {
        userId: string,
        scopePath: string,
        resourceId: string,
    }) {
        if (!request.scopePath.startsWith("/")) {
            throw new TypeError("Scope path must start with /")
        }

        const matchingScope = this.scopes.find(s => {
            return s.path.startsWith(request.scopePath)
        })
        if (!matchingScope) {
            return false
        }

        const resourceInScope = await this.tx.iAMResource.findFirst({
            where: {
                scopeId: matchingScope.id,
                resourceId: request.resourceId,
            },
            include: {
                grants: true,
            }
        })
        if (!resourceInScope) {
            return false
        }

        const matchingGrant = resourceInScope.grants.find(g => {
            return g.userId === request.userId
        })
        return matchingGrant !== undefined
    }
}
