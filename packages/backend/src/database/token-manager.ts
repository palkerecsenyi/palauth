import type { OAuthClientController } from "./oauth.js"
import type { AuthorizationCodeWithOriginal } from "../helpers/oidc/authorization-code.js"
import { DBClient } from "./client.js"
import { createHash, randomBytes } from "crypto"
import type { OAuthToken } from "./generated-models/index.js"
import { DateTime } from "luxon"
import type { IDToken } from "../types/oidc.js"
import { getProjectOIDCID } from "../helpers/constants/hostname.js"
import { JWTSigner } from "../helpers/oidc/jwt.js"
import type { OAuthTokenWrapper } from "./tokens.js"
import { calculateTokenExpiry } from "../helpers/constants/token-duration.js"
import GroupsController from "./groups.js"
import type { TransactionType } from "../types/prisma.js"

export class TokenManager {
    userId: string
    clientController: OAuthClientController
    tx: TransactionType
    private constructor(
        userId: string,
        clientController: OAuthClientController,
        tx: TransactionType,
    ) {
        this.userId = userId
        this.clientController = clientController
        this.tx = tx
    }

    static fromOAuthClientController(
        clientController: OAuthClientController,
        userId: string,
        tx: TransactionType = DBClient.getClient(),
    ) {
        return new TokenManager(userId, clientController, tx)
    }

    static generateCode() {
        const buf = randomBytes(64)
        return buf.toString("hex")
    }

    private async createToken({
        type,
        expires,
        fromCode,
        scopes,
    }: Pick<OAuthToken, "type" | "fromCode"> & {
        expires: DateTime
        scopes: string[]
    }) {
        const code = TokenManager.generateCode()
        const tokenObject = await this.tx.oAuthToken.create({
            data: {
                type,
                value: code,
                expires: expires.toJSDate(),
                fromCode,
                userId: this.userId,
                clientId: this.clientController.getClient().clientId,
                scopes: {
                    create: scopes.map((scope) => ({
                        scope,
                    })),
                },
            },
        })

        return {
            tokenObject,
            code,
        }
    }

    async codeExchange(data: AuthorizationCodeWithOriginal) {
        const hashedCode = createHash("sha256")
            .update(data.originalCode)
            .digest("hex")

        const existingCodeUsage = await this.tx.oAuthToken.findFirst({
            where: {
                OR: [
                    {
                        fromCode: data.originalCode,
                    },
                    {
                        fromCode: hashedCode,
                    },
                ],
            },
        })
        if (existingCodeUsage) {
            throw new Error("code already used")
        }

        const scopes = data.scope.split(" ")
        const accessToken = await this.createToken({
            type: "Access",
            expires: calculateTokenExpiry("Access"),
            fromCode: hashedCode,
            scopes,
        })
        const refreshToken = await this.createToken({
            type: "Refresh",
            expires: calculateTokenExpiry("Refresh"),
            scopes,
            fromCode: null,
        })

        return {
            accessToken,
            refreshToken,
        }
    }

    refresh(refreshToken: OAuthTokenWrapper) {
        return this.createToken({
            type: "Access",
            expires: calculateTokenExpiry("Access"),
            fromCode: null,
            scopes: refreshToken.scopes,
        })
    }

    async generateIdToken(expires: DateTime, nonce?: string) {
        const clientId = this.clientController.getClient().clientId
        const groups = await GroupsController.listGroupsForToken(
            clientId,
            this.userId,
        )

        const idToken: IDToken = {
            iss: getProjectOIDCID(),
            sub: this.userId,
            aud: clientId,
            exp: expires.toUnixInteger(),
            iat: DateTime.now().toUnixInteger(),
            "https://auth.palk.me/groups": groups.map((g) => g.systemName),
            nonce,
        }

        return JWTSigner.sign(idToken)
    }

    static async parseIdToken(idToken: string) {
        const payload = await JWTSigner.parse(idToken, true)
        if (!payload) {
            return undefined
        }

        if (
            [
                payload.iss,
                payload.sub,
                payload.aud,
                payload.exp,
                payload.iat,
            ].some((e) => e === undefined)
        ) {
            return undefined
        }

        if (payload["https://auth.palk.me/groups"] === undefined) {
            payload["https://auth.palk.me/groups"] = []
        } else if (!Array.isArray(payload["https://auth.palk.me/groups"])) {
            return undefined
        }

        return payload as IDToken
    }

    async revokeAllAccess() {
        const query = [
            {
                userId: {
                    equals: this.userId,
                },
            },
            {
                clientId: {
                    equals: this.clientController.getClient().clientId,
                },
            },
        ]

        await this.tx.userOAuthGrant.deleteMany({
            where: {
                AND: query,
            },
        })

        await this.tx.oAuthToken.deleteMany({
            where: {
                AND: query,
            },
        })
    }
}
