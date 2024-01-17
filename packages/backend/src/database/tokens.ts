import {Prisma} from "./generated-models/index.js";
import {DBClient} from "./client.js";
import {NextFunction, Response} from "express";
import {DateTime} from "luxon";
import {BearerTokenRequest} from "../types/express.js";
import {UserController} from "./users.js";

type OAuthTokenWrapperData = Prisma.OAuthTokenGetPayload<{
    include: {scopes: true}
}>

export class OAuthTokenWrapper {
    data: OAuthTokenWrapperData
    private constructor(data: OAuthTokenWrapperData) {
        this.data = data
    }

    static async fromTokenValue(value: string) {
        const dbClient = DBClient.getClient()
        const tokenObj = await dbClient.oAuthToken.findFirst({
            where: {
                value,
            },
            include: {
                scopes: true,
            }
        })
        if (!tokenObj) {
            return undefined
        }

        return new OAuthTokenWrapper(tokenObj)
    }

    static fromToken(token: OAuthTokenWrapperData) {
        return new OAuthTokenWrapper(token)
    }

    get isValid() {
        return DateTime.fromJSDate(this.data.expires) > DateTime.now()
    }

    get scopes() {
        return this.data.scopes.map(e => e.scope)
    }

    hasScope(scope: string) {
        return this.scopes.includes(scope)
    }

    getUser() {
        return UserController.getById(this.data.userId)
    }

    get userId() {
        return this.data.userId
    }

    belongsToClient(clientId: string) {
        return this.data.clientId === clientId
    }

    get isAccessToken() {
        return this.data.type === "Access"
    }

    get isRefreshToken() {
        return this.data.type === "Refresh"
    }

    async mustGetUser() {
        const u = await this.getUser()
        if (!u) {
            throw new Error("Token user not found")
        }

        return u
    }

    static middleware(
        requiredScopes: string[]
    ) {
        return async (req: BearerTokenRequest, res: Response, next: NextFunction) => {
            const authHeader = req.headers.authorization
            if (!authHeader) {
                // https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
                res.setHeader("WWW-Authenticate", `Bearer error="invalid_request"`)
                res.sendStatus(401)
                return
            }

            if (!authHeader.startsWith("Bearer ")) {
                // https://datatracker.ietf.org/doc/html/rfc6750#section-3
                res.setHeader("WWW-Authenticate", `Bearer error="invalid_token"`)
                res.sendStatus(401)
                return
            }

            const bearerToken = authHeader.substring(7)
            const tokenWrapper = await OAuthTokenWrapper.fromTokenValue(bearerToken)
            if (!tokenWrapper) {
                res.setHeader("WWW-Authenticate", `Bearer error="invalid_token"`)
                res.sendStatus(401)
                return
            }

            // cannot use a refresh token for authenticating requests
            if (tokenWrapper.isRefreshToken) {
                res.setHeader("WWW-Authenticate", `Bearer error="invalid_token", error_description="Cannot use a refresh token"`)
                res.sendStatus(401)
                return
            }

            if (!tokenWrapper.isValid) {
                res.setHeader("WWW-Authenticate", `Bearer error="invalid_token", error_description="Token expired"`)
                res.sendStatus(401)
                return
            }

            const scopesMet = requiredScopes.every(requiredScope => tokenWrapper.scopes.includes(requiredScope))
            if (!scopesMet) {
                res.setHeader("WWW-Authenticate", `Bearer error="insufficient_scope"`)
                res.sendStatus(401)
                return
            }

            req.tokenWrapper = tokenWrapper
            next()
        }
    }
}