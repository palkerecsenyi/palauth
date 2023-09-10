import {OAuthClient, Prisma, PrismaClient, User} from "./generated-models/index.js";
import argon2 from "argon2"
import {DBClient, InterruptibleTransaction} from "./client.js";
import {TransactionType} from "../types/prisma.js";
import {OIDCUserInfoResponse} from "../types/oidc.js";

export type UserControllerUser = Prisma.UserGetPayload<{
    include: {oauthGrants: {include: {client: true}}}
}>
export class UserController {
    static async createUser(
        {
            displayName, email, password,
        }: Pick<User, "displayName" | "email"> & {
            password: string
        },
        tx?: TransactionType
    ) {
        const passwordHash = await argon2.hash(password)

        const client = tx ?? DBClient.getClient()
        const user = await client.user.create({
            data: {
                displayName, email, passwordHash,
            }
        })

        return user.id
    }

    user: UserControllerUser
    private constructor(user: UserControllerUser) {
        this.user = user
    }
    static for(user: UserControllerUser) {
        return new UserController(user)
    }

    static getById(userId: string, client: PrismaClient | InterruptibleTransaction = DBClient.getClient()) {
        return client.user.findFirst({
            where: {
                id: userId,
            },
            include: {
                oauthGrants: {
                    include: {
                        client: true,
                    },
                },
            }
        })
    }

    static getByEmail(email: string) {
        const client = DBClient.getClient()
        return client.user.findFirst({
            where: {
                email,
            },
            include: {
                oauthGrants: {
                    include: {
                        client: true,
                    }
                },
            }
        })
    }

    checkPassword(password: string) {
        return argon2.verify(this.user.passwordHash, password)
    }

    toUserInfo(includeEmail: boolean): OIDCUserInfoResponse {
        const obj: OIDCUserInfoResponse = {
            sub: this.user.id,
            name: this.user.displayName,
        }
        if (includeEmail) {
            obj.email = this.user.email
            obj.email_verified = true
        }
        return obj
    }

    scopesByClient() {
        const clients: {
            client: OAuthClient
            scopes: string[]
        }[] = []
        for (const grant of this.user.oauthGrants) {
            const existingClient = clients.find(e => e.client.clientId === grant.clientId)
            if (existingClient) {
                existingClient.scopes.push(grant.scope)
            } else {
                clients.push({
                    client: grant.client,
                    scopes: [grant.scope],
                })
            }
        }

        return clients
    }
}