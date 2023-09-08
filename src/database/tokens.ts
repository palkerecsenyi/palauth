import {OAuthClientController} from "./oauth.js";
import {AuthorizationCodeWithOriginal} from "../helpers/oidc/authorization-code.js";
import {DBClient} from "./client.js";
import {randomBytes} from "crypto";
import {OAuthToken} from "./generated-models/index.js";
import {DateTime} from "luxon";
import {IDToken} from "../types/oidc.js";
import {getProjectOIDCID} from "../helpers/hostname.js";
import {JWTSigner} from "../helpers/oidc/jwt.js";

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

    private static generateCode() {
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
        const dbClient = DBClient.getClient()
        const existingCodeUsage = await dbClient.oAuthToken.findFirst({
            where: {
                fromCode: data.originalCode,
            }
        })
        if (existingCodeUsage) {
            throw new Error("code already used")
        }

        return this.createToken({
            type: "Access",
            expires: DateTime.now().plus({ day: 3 }),
            fromCode: data.originalCode,
            scopes: data.scope.split(" "),
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
}