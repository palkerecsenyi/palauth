import {OAuthClient, Prisma} from "./generated-models/index.js";
import {DBClient} from "./client.js";
import argon2 from "argon2";
import {TokenManager} from "./token-manager.js";
import {TransactionType} from "../types/prisma.js";
import {Request, Response} from "express";
import {OAuthAccessTokenResponse} from "../types/oidc.js";

export type OAuthControllerClient = Prisma.OAuthClientGetPayload<{
    include: { redirectURIs: true, admin: true, },
}>

export class OAuthClientController {
    private readonly oauthClient: OAuthControllerClient
    private dbClient: TransactionType
    private constructor(client: OAuthControllerClient, dbClient: TransactionType) {
        this.oauthClient = client
        this.dbClient = dbClient
    }

    static async getByClientId(clientId: string, dbClient: TransactionType = DBClient.getClient()) {
        try {
            const oauthClient = await dbClient.oAuthClient.findFirst({
                where: {
                    clientId,
                },
                include: {
                    redirectURIs: true,
                    admin: true,
                }
            })
            if (!oauthClient) return undefined
            return new OAuthClientController(oauthClient, dbClient)
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

    async checkClientSecretFromHeaders(req: Request, res: Response) {
        let { client_secret } = req.body
        if (!client_secret) {
            const authHeader = req.headers.authorization
            if (authHeader?.startsWith("Basic ")) {
                client_secret = authHeader.substring(6)
            }
        }

        if (typeof client_secret !== "string") {
            res.json({
                error: "invalid_client",
            } as OAuthAccessTokenResponse)
            return false
        }
        const secretCorrect = await this.checkClientSecret(client_secret)
        if (!secretCorrect) {
            res.json({
                error: "invalid_client",
            } as OAuthAccessTokenResponse)
            return false
        }

        return true
    }

    checkRedirectURI(redirectURI: string) {
        return this.oauthClient.redirectURIs.find(e => e.uri === redirectURI) !== undefined
    }

    getTokenManager(userId: string) {
        return TokenManager.fromOAuthClientController(this, userId)
    }

    private static async generateClientSecret() {
        const raw = TokenManager.generateCode()
        return {
            raw,
            hashed: await argon2.hash(raw)
        }
    }

    static async create(data: Pick<OAuthClient, "name" | "usageDescription" | "adminId">, dbClient: TransactionType = DBClient.getClient()) {
        const {raw, hashed} = await this.generateClientSecret()

        const newClient = await dbClient.oAuthClient.create({
            data: {
                adminId: data.adminId,
                name: data.name,
                usageDescription: data.usageDescription,
                clientSecretHash: hashed,
            }
        })

        return {
            clientId: newClient.clientId,
            clientSecret: raw,
        }
    }

    async delete() {
        await this.dbClient.oAuthClient.delete({
            where: {
                clientId: this.oauthClient.clientId,
            }
        })
    }

    async update(data: Pick<OAuthClient, "usageDescription">) {
        await this.dbClient.oAuthClient.update({
            where: {
                clientId: this.oauthClient.clientId,
            },
            data: {
                usageDescription: data.usageDescription,
            },
        })
    }

    addRedirectURI(uri: string) {
        return this.dbClient.oAuthClientRedirectURI.create({
            data: {
                clientId: this.oauthClient.clientId,
                uri,
            }
        })
    }

    async deleteRedirectURI(id: string) {
        await this.dbClient.oAuthClientRedirectURI.delete({
            where: {
                id,
            }
        })
    }
}