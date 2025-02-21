import type { NextFunction, Request, Response } from "express"
import type { OIDCFlowRequest } from "../../types/express.js"
import {
    type OAuthAuthorizationError,
    type OIDCPromptType,
    type OIDCResponseType,
    OIDCResponseTypes,
    OIDCScopes,
} from "../../types/oidc.js"
import { DBClient } from "../../database/client.js"
import { URLSearchParams } from "node:url"
import { AuthorizationCode } from "./authorization-code.js"
import type { TransactionType } from "../../types/prisma.js"
import { OAuthClientController } from "../../database/oauth.js"
import { TokenManager } from "../../database/token-manager.js"
import { calculateTokenExpiry } from "../constants/token-duration.js"

export interface OIDCFlowData {
    client_id: string
    response_type: OIDCResponseType
    redirect_uri: string
    scope: string
    nonce?: string
    prompt?: OIDCPromptType
    state?: string
}

export class OIDCFlow {
    flowData: OIDCFlowData

    private constructor(data: OIDCFlowData) {
        this.flowData = data
    }

    private static validateAndConstruct({
        client_id,
        response_type,
        redirect_uri,
        scope,
        nonce,
        prompt,
        state,
    }: Record<string, unknown>) {
        if (typeof client_id !== "string") {
            throw new Error("client_id not provided")
        }
        if (typeof response_type !== "string") {
            throw new Error("response_type is not provided")
        }
        if (!OIDCResponseTypes.supportedResponseTypes.includes(response_type)) {
            throw new Error("response_type must be 'code' or 'id_token'")
        }
        if (typeof redirect_uri !== "string") {
            throw new Error("redirect_uri is not provided")
        }
        if (typeof scope !== "string") {
            throw new Error("scope is not provided")
        }

        if (
            scope
                .split(" ")
                .some((s) => !OIDCScopes.supportedScopes.includes(s))
        ) {
            throw new Error("scope not recognised")
        }

        if (nonce !== undefined && typeof nonce !== "string") {
            throw new Error("nonce is not a valid string")
        }
        if (
            prompt !== undefined &&
            (typeof prompt !== "string" || !["none", "login"].includes(prompt))
        ) {
            throw new Error("prompt must be 'none', 'login', or unspecified")
        }
        if (state !== undefined && typeof state !== "string") {
            throw new Error("state is not a valid string")
        }

        return new OIDCFlow({
            client_id,
            response_type: response_type as OIDCResponseType,
            redirect_uri,
            scope,
            nonce,
            prompt: prompt as OIDCPromptType,
            state,
        })
    }

    static fromRequest(req: Request) {
        const {
            client_id,
            response_type,
            redirect_uri,
            scope,
            nonce,
            prompt,
            state,
        } = req.query
        return OIDCFlow.validateAndConstruct({
            client_id,
            response_type,
            redirect_uri,
            scope,
            nonce,
            prompt,
            state,
        })
    }

    static middleware() {
        return (req: OIDCFlowRequest, res: Response, next: NextFunction) => {
            const obj = req.session.oidcFlow
            if (!obj) {
                res.status(400).send("missing oidc_flow in session")
                return
            }

            try {
                req.oidcFlow = OIDCFlow.fromJSON(
                    obj as unknown as Record<string, unknown>,
                )
            } catch (e) {
                req.session.oidcFlow = undefined
                console.error(e)
                res.sendStatus(500)
                return
            }

            next()
        }
    }

    save(req: Request) {
        req.session.oidcFlow = this.toJSON()
    }

    end(req: Request) {
        if (req.session.oidcFlow) {
            req.session.oidcFlow = undefined
        }
    }

    get scopes() {
        return this.flowData.scope.split(" ")
    }

    get isOpenID() {
        return this.scopes.includes("openid")
    }

    get isImplicit() {
        return this.flowData.response_type === "id_token"
    }

    /**
     * Returns a subset of the requested scopes that have not yet been granted by the user, as well as the scopes
     * that have been granted.
     * @param userId - The user to check the scopes of
     */
    async checkScopeGrantStatus(userId: string) {
        const dbClient = DBClient.getClient()
        const grantedScopes = await dbClient.userOAuthGrant.findMany({
            where: {
                userId,
                clientId: this.flowData.client_id,
            },
        })

        return {
            nonGrantedScopes: this.scopes.filter(
                (s) => grantedScopes.find((e) => e.scope === s) === undefined,
            ),
            grantedScopes: grantedScopes.map((e) => e.scope),
        }
    }

    async grantScopes(scopes: string[], userId: string) {
        const dbClient = DBClient.getClient()
        await dbClient.userOAuthGrant.createMany({
            data: scopes.map((s) => {
                return {
                    scope: s,
                    userId,
                    clientId: this.flowData.client_id,
                }
            }),
        })
    }

    errorExitURL(code: OAuthAuthorizationError, description: string) {
        const q = new URLSearchParams()
        q.append("error", code)
        q.append("description", description)
        return `${this.flowData.redirect_uri}?${q.toString()}`
    }

    async successExitURL(
        userId: string,
        tx: TransactionType = DBClient.getClient(),
    ) {
        const url = this.flowData.redirect_uri
        const q = new URLSearchParams()
        const state = this.flowData.state
        if (state) {
            q.append("state", state)
        }

        if (this.isImplicit) {
            const clientController = await this.oauthClientController(tx)
            if (!clientController)
                throw new Error("failed to init OAuth Client Controller")
            const tokenManager = TokenManager.fromOAuthClientController(
                clientController,
                userId,
                tx,
            )
            const idToken = await tokenManager.generateIdToken(
                calculateTokenExpiry("Access"),
                this.flowData.nonce,
            )

            q.append("id_token", idToken)
        } else {
            const authCode = new AuthorizationCode({
                userId,
                clientId: this.flowData.client_id,
                scope: this.flowData.scope,
                redirectURI: this.flowData.redirect_uri,
                nonce: this.flowData.nonce,
            })
            q.append("code", await authCode.sign())
        }

        return `${url}?${q.toString()}`
    }

    toJSON() {
        return this.flowData
    }

    oauthClientController(tx: TransactionType = DBClient.getClient()) {
        return OAuthClientController.getByClientId(this.flowData.client_id, tx)
    }

    static fromJSON(json: Record<string, unknown>) {
        return OIDCFlow.validateAndConstruct(json)
    }
}
