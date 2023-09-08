import {NextFunction, Request, Response} from "express";
import {OIDCFlowRequest} from "../../types/express.js";
import {OAuthAuthorizationError, OIDCPromptType, OIDCResponseType} from "../../types/oidc.js";
import {DBClient} from "../../database/client.js";
import {URLSearchParams} from "url";
import {AuthorizationCode} from "./authorization-code.js";

export class OIDCFlow {
    client_id: string
    response_type: OIDCResponseType
    redirect_uri: string
    scope: string
    nonce?: string
    prompt?: OIDCPromptType
    state?: string

    private constructor(
        client_id: string,
        response_type: OIDCResponseType,
        redirect_uri: string,
        scope: string,
        nonce?: string,
        prompt?: OIDCPromptType,
        state?: string,
    ) {
        this.client_id = client_id
        this.response_type = response_type
        this.redirect_uri = redirect_uri
        this.scope = scope
        this.nonce = nonce
        this.prompt = prompt
        this.state = state
    }

    private static validateAndConstruct(
        {
            client_id,
            response_type,
            redirect_uri,
            scope,
            nonce,
            prompt,
            state,
        }: Record<string, any>
    ) {
        if (typeof client_id !== "string") {
            throw new Error("client_id not provided")
        }
        if (typeof response_type !== "string") {
            throw new Error("response_type is not provided")
        }
        if (!["code"].includes(response_type)) {
            throw new Error("response_type must be 'code'")
        }
        if (typeof redirect_uri !== "string") {
            throw new Error("redirect_uri is not provided")
        }
        if (typeof scope !== "string") {
            throw new Error("scope is not provided")
        }

        if (nonce !== undefined && typeof nonce !== "string") {
            throw new Error("nonce is not a valid string")
        }
        if (prompt !== undefined && !["none", "login"].includes(prompt)) {
            throw new Error("prompt must be 'none', 'login', or unspecified")
        }
        if (state !== undefined && typeof state !== "string") {
            throw new Error("state is not a valid string")
        }

        return new OIDCFlow(
            client_id,
            response_type as OIDCResponseType,
            redirect_uri,
            scope,
            nonce,
            prompt,
            state,
        )
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
        return this.validateAndConstruct({
            client_id, response_type, redirect_uri, scope, nonce, prompt, state,
        })
    }

    static middleware() {
        return (req: OIDCFlowRequest, res: Response, next: NextFunction) => {
            const obj = req.session!["oidc_flow"]
            if (!obj) {
                res.status(400).send("missing oidc_flow in session")
                return
            }

            try {
                req.oidcFlow = OIDCFlow.fromJSON(obj)
            } catch (e) {
                delete req.session!["oidc_flow"]
                console.error(e)
                res.sendStatus(500)
                return
            }

            next()
        }
    }

    save(req: Request) {
        req.session!["oidc_flow"] = this.toJSON()
    }

    end(req: Request) {
        if (req.session!["oidc_flow"]) {
            delete req.session!["oidc_flow"]
        }
    }

    get scopes() {
        return this.scope.split(" ")
    }

    get isOpenID() {
        return this.scopes.includes("openid")
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
                clientId: this.client_id,
            }
        })

        return {
            nonGrantedScopes: this.scopes.filter(s => grantedScopes.find(e => e.scope === s) === undefined),
            grantedScopes: grantedScopes.map(e => e.scope),
        }
    }

    async grantScopes(scopes: string[], userId: string) {
        const dbClient = DBClient.getClient()
        await dbClient.userOAuthGrant.createMany({
            data: scopes.map(s => {
                return {
                    scope: s,
                    userId,
                    clientId: this.client_id,
                }
            })
        })
    }

    errorExitURL(code: OAuthAuthorizationError, description: string) {
        const q = new URLSearchParams()
        q.append("error", code)
        q.append("description", description)
        return this.redirect_uri + "?" + q.toString()
    }

    successExitURL(userId: string) {
        const authCode = new AuthorizationCode({
            userId,
            clientId: this.client_id,
            scope: this.scope,
            redirectURI: this.redirect_uri,
            nonce: this.nonce,
        }).sign()
        const q = new URLSearchParams()
        q.append("code", authCode)
        if (this.state) {
            q.append("state", this.state)
        }
        return this.redirect_uri + "?" + q.toString()
    }

    toJSON() {
        return {
            client_id: this.client_id,
            response_type: this.response_type,
            redirect_uri: this.redirect_uri,
            scope: this.scope,
            nonce: this.nonce,
            prompt: this.prompt,
        }
    }

    static fromJSON(json: Record<string, any>) {
        return this.validateAndConstruct(json)
    }
}