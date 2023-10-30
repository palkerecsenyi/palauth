import {OAuthClientController} from "./oauth.js";
import {AuthorizationCodeWithOriginal} from "../helpers/oidc/authorization-code.js";
import {DBClient} from "./client.js";
import {createHash, randomBytes} from "crypto";
import {OAuthToken} from "./generated-models/index.js";
import {DateTime} from "luxon";
import {IDToken} from "../types/oidc.js";
import {getProjectOIDCID} from "../helpers/constants/hostname.js";
import {JWTSigner} from "../helpers/oidc/jwt.js";
import {OAuthTokenWrapper} from "./tokens.js";
import {calculateTokenExpiry} from "../helpers/constants/token-duration.js";

export class TokenManager {
    userId: string
    clientController: OAuthClientController
    private constructor(userId: string, clientController: OAuthClientController) {
        this.userId = userId
        this.clientController = clientController
    }

    static fromOAuthClientController(clientController: OAuthClientController, userId: string) {
        return new TokenManager(userId, clientController)
    }

    static generateCode() {
        const buf = randomBytes(64)
        return buf.toString("hex")
    }

    private async createToken(
        {
            type,
            expires,
            fromCode,
            scopes,
        }: Pick<OAuthToken, "type" | "fromCode"> & {
            expires: DateTime
            scopes: string[]
        }
    ) {
        const dbClient = DBClient.getClient()
        const code = TokenManager.generateCode()
        const tokenObject = await dbClient.oAuthToken.create({
            data: {
                type,
                value: code,
                expires: expires.toJSDate(),
                fromCode,
                userId: this.userId,
                clientId: this.clientController.getClient().clientId,
                scopes: {
                    create: scopes.map(scope => ({
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
        const hashedCode = createHash("sha256").update(data.originalCode).digest("hex")

        const dbClient = DBClient.getClient()
        const existingCodeUsage = await dbClient.oAuthToken.findFirst({
            where: {
                OR: [
                    {
                        fromCode: data.originalCode,
                    },
                    {
                        fromCode: hashedCode,
                    }
                ]
            }
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
            accessToken, refreshToken,
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

    generateIdToken(expires: DateTime, nonce?: string) {
        const idToken: IDToken = {
            iss: getProjectOIDCID(),
            sub: this.userId,
            aud: this.clientController.getClient().clientId,
            exp: expires.toUnixInteger(),
            iat: DateTime.now().toUnixInteger(),
            nonce,
        }

        return JWTSigner.sign(idToken)
    }

    static async parseIdToken(idToken: string) {
        const payload = await JWTSigner.parse(idToken, true)
        if (!payload) {
            return undefined
        }

        if ([
            payload.iss,
            payload.sub,
            payload.aud,
            payload.exp,
            payload.iat,
        ].some(e => e === undefined)) {
            return undefined
        }

        return payload as IDToken
    }

    async revokeAllAccess() {
        return await DBClient.interruptibleTransaction(async tx => {
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

            await tx.userOAuthGrant.deleteMany({
                where: {
                    AND: query,
                }
            })

            await tx.oAuthToken.deleteMany({
                where: {
                    AND: query,
                }
            })
        })
    }
}
