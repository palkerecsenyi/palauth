import {OAuthClient, Prisma} from "./generated-models/index.js";
import {DBClient} from "./client.js";
import argon2 from "argon2";
import {TokenManager} from "./token-manager.js";
import {TransactionType} from "../types/prisma.js";
import {Request, Response} from "express";
import {OAuthAccessTokenResponse} from "../types/oidc.js";
import { getProjectOIDCID } from "../helpers/constants/hostname.js";

export type OAuthControllerClient = Prisma.OAuthClientGetPayload<{
    include: { redirectURIs: true, postLogoutURIs: true, admin: true, },
}>

export class OAuthClientController {
    private readonly oauthClient: OAuthControllerClient
    private tx: TransactionType
    private constructor(client: OAuthControllerClient, dbClient: TransactionType) {
        this.oauthClient = client
        this.tx = dbClient
    }

    static async getByClientId(clientId: string, dbClient: TransactionType = DBClient.getClient()) {
        try {
            const oauthClient = await dbClient.oAuthClient.findFirst({
                where: {
                    clientId,
                },
                include: {
                    redirectURIs: true,
                    postLogoutURIs: true,
                    admin: true,
                }
            })
            if (!oauthClient) return undefined
            return new OAuthClientController(oauthClient, dbClient)
        } catch (e) {
            return undefined
        }
    }

    static async getAllPublicClients(dbClient: TransactionType = DBClient.getClient()) {
        const clients = await dbClient.oAuthClient.findMany({
            where: {
                initiateURI: {
                    not: null,
                }
            },
            include: {
                redirectURIs: true,
                postLogoutURIs: true,
                admin: true,
            }
        })
        return clients.map(c => new OAuthClientController(c, dbClient))
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
                const base64Auth = authHeader.substring(6)
                const decodedAuth = Buffer.from(base64Auth, "base64").toString("utf-8").split(":")
                if (decodedAuth.length !== 2) {
                    res.json({
                        error: "invalid_request",
                        error_description: "Did not understand Authorization header"
                    } as OAuthAccessTokenResponse)
                    return
                }

                const [, decodedClientSecret] = decodedAuth
                client_secret = decodedClientSecret
            } else if (authHeader?.startsWith("Bearer ")) {
                const decodedSecret = authHeader.substring(7)
                if (decodedSecret.length === 0) {
                    res.json({
                        error: "invalid_request",
                        error_description: "Bearer token not long enough"
                    } as OAuthAccessTokenResponse)
                    return
                }

                client_secret = decodedSecret
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

    checkPostLogoutURI(postLogoutURI: string) {
        return this.oauthClient.postLogoutURIs.find(e => e.uri === postLogoutURI) !== undefined
    }

    get isPublic() {
        return this.oauthClient.initiateURI !== null
    }
    
    generateInitiateURI() {
        if (!this.isPublic) {
            throw new Error("Cannot initiate a non-public client")
        }

        const baseURI = this.oauthClient.initiateURI!
        return `${baseURI}?iss=${getProjectOIDCID()}`
    }

    getTokenManager(userId: string) {
        return TokenManager.fromOAuthClientController(this, userId, this.tx)
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
        await this.tx.oAuthClient.delete({
            where: {
                clientId: this.oauthClient.clientId,
            }
        })
    }

    async update(data: Pick<OAuthClient, "usageDescription">) {
        await this.tx.oAuthClient.update({
            where: {
                clientId: this.oauthClient.clientId,
            },
            data: {
                usageDescription: data.usageDescription,
            },
        })
    }

    addRedirectURI(uri: string) {
        return this.tx.oAuthClientRedirectURI.create({
            data: {
                clientId: this.oauthClient.clientId,
                uri,
            }
        })
    }

    async deleteRedirectURI(id: string) {
        await this.tx.oAuthClientRedirectURI.delete({
            where: {
                id,
            }
        })
    }
}
