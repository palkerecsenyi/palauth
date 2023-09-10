import {Prisma} from "./generated-models/index.js";
import {DBClient} from "./client.js";
import argon2 from "argon2";
import {TokenManager} from "./token-manager.js";

type OAuthControllerClient = Prisma.OAuthClientGetPayload<{
    include: { redirectURIs: true, admin: true, },
}>

export class OAuthClientController {
    private readonly oauthClient: OAuthControllerClient
    private constructor(client: OAuthControllerClient) {
        this.oauthClient = client
    }

    static async getByClientId(clientId: string) {
        const client = DBClient.getClient()
        try {
            const oauthClient = await client.oAuthClient.findFirst({
                where: {
                    clientId,
                },
                include: {
                    redirectURIs: true,
                    admin: true,
                }
            })
            if (!oauthClient) return undefined
            return new OAuthClientController(oauthClient)
        } catch (e) {
            return undefined
        }
    }

    getClient() {
        return this.oauthClient
    }

    checkClientSecret(secret: string) {
        return argon2.verify(this.oauthClient.clientSecretHash, secret)
    }

    checkRedirectURI(redirectURI: string) {
        return this.oauthClient.redirectURIs.find(e => e.uri === redirectURI) !== undefined
    }

    getTokenManager(userId: string) {
        return TokenManager.fromOAuthClientController(this, userId)
    }
}