import {$Enums, OAuthClient, Prisma, User} from "./generated-models/index.js";
import argon2 from "argon2"
import {DBClient} from "./client.js";
import {TransactionType} from "../types/prisma.js";
import {OIDCUserInfoResponse} from "../types/oidc.js";
import TwoFactorController from "../helpers/2fa/2fa.js";

export type UserControllerUser = Prisma.UserGetPayload<{
    include: {
        oauthGrants: {include: {client: true}},
        ownedClients: true,
        secondFactors: true,
    }
}>
export class UserController {
    static async createUser(
        {
            displayName, email, password,
        }: Pick<User, "displayName" | "email"> & {
            password: string
        },
        autoVerifyEmail = false,
        tx: TransactionType = DBClient.getClient(),
    ) {
        const passwordHash = await argon2.hash(password)

        const user = await tx.user.create({
            data: {
                displayName, email, passwordHash,
                emailVerified: autoVerifyEmail,
            }
        })

        return user.id
    }

    user: UserControllerUser
    transaction: TransactionType
    private constructor(user: UserControllerUser, transaction: TransactionType) {
        this.user = user
        this.transaction = transaction
    }
    static for(user: UserControllerUser, transaction: TransactionType = DBClient.getClient()) {
        return new UserController(user, transaction)
    }

    static getById(userId: string, client: TransactionType = DBClient.getClient()) {
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
                ownedClients: true,
                secondFactors: true,
            }
        })
    }

    static getByEmail(email: string, client: TransactionType = DBClient.getClient()) {
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
                ownedClients: true,
                secondFactors: true,
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

    get requiresTwoFactor() {
        return this.user.secondFactors.length !== 0
    }

    get twoFactorMethods() {
        const tfaMethodSet = new Set<$Enums.SecondAuthenticationFactorType>()
        for (const f of this.user.secondFactors) {
            tfaMethodSet.add(f.type)
        }
        return [...tfaMethodSet.values()]
    }

    getTwoFactorController() {
        return TwoFactorController.forUser(this.user, this.transaction)
    }
    get hasPasskey() {
        const tfa = this.getTwoFactorController()
        return tfa.registrationOfTypeExists("SecurityKey") && tfa.securityKey.hasPasskey
    }
}
