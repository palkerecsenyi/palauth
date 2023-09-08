import express, {Response} from "express";
import {OAuthClientController} from "../database/oauth.js";
import {OIDCFlow} from "../helpers/oidc/oidc-flow.js";
import {authMiddleware, setUserId} from "../helpers/auth.js";
import {AuthenticatedRequest, OIDCFlowRequest} from "../types/express.js";
import {OAuthAccessTokenResponse} from "../types/oidc.js";
import {AuthorizationCode} from "../helpers/oidc/authorization-code.js";
import {OAuthToken} from "../database/generated-models/index.js";
import {DateTime} from "luxon";

const oidcRouter = express.Router()

const oauthErrorPage = (res: Response, error: any) => {
    let errorMessage = "Unknown error; see server logs"
    if (error instanceof Error) {
        errorMessage = error.message
    } else if (typeof error === "string") {
        errorMessage = error
    }

    res.status(400)
    return res.render("oauth/error.pug", {
        errorMessage,
    })
}

oidcRouter.get(
    "/auth",
    authMiddleware({
        authRequirement: "none",
    }),
    async (req: AuthenticatedRequest, res) => {
        let flow: OIDCFlow
        try {
            flow = OIDCFlow.fromRequest(req)
        } catch (e) {
            return oauthErrorPage(res, e)
        }

        const oauthClient = await OAuthClientController.getByClientId(flow.client_id as string)
        if (!oauthClient) {
            return oauthErrorPage(res, "client_id invalid or not found")
        }

        if (!oauthClient.checkRedirectURI(flow.redirect_uri)) {
            return oauthErrorPage(res, "redirect_uri is not acceptable for the client")
        }

        if (!flow.isOpenID) {
            return oauthErrorPage(res, "For now, only OIDC requests are supported. Please add the openid scope.")
        }

        flow.save(req)

        const u = req.user
        if (!u || flow.prompt === "login") {
            if (flow.prompt === "none") {
                return oauthErrorPage(res, "prompt='none' but there is no authenticated user")
            }

            setUserId(req, undefined)
            res.redirect(
                "/auth/signin?destination=/oidc/auth/sign-in-callback"
            )
            return
        }

        res.redirect("/oidc/auth/sign-in-callback")
    }
)

oidcRouter.get(
    "/auth/sign-in-callback",
    authMiddleware({
        authRequirement: "require-authenticated",
        redirectTo: "/oidc/auth/sign-in-callback",
    }),
    OIDCFlow.middleware(),
    async (req: AuthenticatedRequest & OIDCFlowRequest, res) => {
        const flow = req.oidcFlow!

        const ungrantedScopes = await flow.checkScopeGrantStatus(req.user!.id)
        if (ungrantedScopes.length === 0) {
            res.redirect(flow.successExitURL(req.user!.id))
            return
        }

        res.redirect("/oidc/auth/grant-scopes")
    }
)

oidcRouter.get(
    "/auth/grant-scopes",
    authMiddleware({
        authRequirement: "require-authenticated",
        redirectTo: "/oidc/auth/sign-in-callback"
    }),
    OIDCFlow.middleware(),
    async (req: AuthenticatedRequest & OIDCFlowRequest, res) => {
        const flow = req.oidcFlow!

        const scopesToGrant = await flow.checkScopeGrantStatus(req.user!.id)
        const clientController = await OAuthClientController.getByClientId(flow.client_id)
        if (!clientController) {
            return oauthErrorPage(res, "client_id invalid or not found")
        }

        res.render("oauth/scopes.pug", {
            client: clientController.getClient(),
            scopesToGrant,
        })
    }
)

oidcRouter.get(
    "/auth/grant-scopes-feedback",
    authMiddleware({
        authRequirement: "require-authenticated",
        redirectTo: "/oidc/auth/sign-in-callback",
    }),
    OIDCFlow.middleware(),
    async (req: AuthenticatedRequest & OIDCFlowRequest, res) => {
        const flow = req.oidcFlow!

        const scopesGranted = req.query.grant === "yes"
        if (!scopesGranted) {
            res.redirect(flow.errorExitURL("access_denied", "client did not grant the requested scope(s)"))
            flow.end(req)
            return
        }

        const scopesToGrant = await flow.checkScopeGrantStatus(req.user!.id)
        await flow.grantScopes(scopesToGrant, req.user!.id)

        res.redirect(flow.successExitURL(req.user!.id))
        flow.end(req)
    }
)

oidcRouter.post(
    "/token",
    async (req, res)  => {
        const {
            grant_type,
            code,
            redirect_uri,
            client_secret,
        } = req.body

        if (grant_type !== "authorization_code") {
            res.json({
                error: "unsupported_grant_type",
                error_description: "Only 'authorization_code' is supported",
            } as OAuthAccessTokenResponse)
            return
        }

        const parsedCode = AuthorizationCode.parse(code)
        if (!parsedCode) {
            res.json({
                error: "invalid_grant"
            } as OAuthAccessTokenResponse)
            return
        }

        if (parsedCode.data.redirectURI !== redirect_uri) {
            res.json({
                error: "invalid_grant"
            } as OAuthAccessTokenResponse)
        }

        const oauthClient = await OAuthClientController.getByClientId(parsedCode.data.clientId)
        if (!oauthClient) {
            res.json({
                error: "invalid_request",
                error_description: "Could not find client specified in code"
            } as OAuthAccessTokenResponse)
            return
        }

        if (typeof client_secret !== "string") {
            res.json({
                error: "invalid_client",
            } as OAuthAccessTokenResponse)
        }
        const secretCorrect = oauthClient.checkClientSecret(client_secret)
        if (!secretCorrect) {
            res.json({
                error: "invalid_client",
            } as OAuthAccessTokenResponse)
        }

        const tm = oauthClient.getTokenManager(parsedCode.data.userId)
        let accessToken: string
        let tokenObject: OAuthToken
        try {
            const response = await tm.codeExchange({
                ...parsedCode.data,
                originalCode: code,
            })
            accessToken = response.code
            tokenObject = response.tokenObject
        } catch (e) {
            console.error(e)
            res.json({
                error: "invalid_grant",
            } as OAuthAccessTokenResponse)
            return
        }

        const tokenExpiry = DateTime.fromJSDate(tokenObject.expires)
        const idToken = tm.generateIdToken(tokenExpiry)

        res.json({
            access_token: accessToken,
            expires_in: Math.round(tokenExpiry.diffNow().as("seconds")),
            token_type: "Bearer",
            id_token: idToken,
        } as OAuthAccessTokenResponse)
    }
)

export default oidcRouter