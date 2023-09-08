import {User} from "./generated-models/index.js";
import argon2 from "argon2"
import {DBClient} from "./client.ts";
import {TransactionType} from "../types/prisma.ts";
import {OIDCUserInfoResponse} from "../types/oidc.js";

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

    user: User
    private constructor(user: User) {
        this.user = user
    }
    static for(user: User) {
        return new UserController(user)
    }

    static getById(userId: string) {
        const client = DBClient.getClient()
        return client.user.findFirst({
            where: {
                id: userId,
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
}