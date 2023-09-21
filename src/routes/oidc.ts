import express, {Response} from "express";
import {OAuthClientController} from "../database/oauth.js";
import {OIDCFlow} from "../helpers/oidc/oidc-flow.js";
import {authMiddleware, setUserId} from "../helpers/auth.js";
import {AuthenticatedRequest, BearerTokenRequest, OIDCFlowRequest} from "../types/express.js";
import {OAuthAccessTokenResponse} from "../types/oidc.js";
import {AuthorizationCode} from "../helpers/oidc/authorization-code.js";
import {OAuthToken} from "../database/generated-models/index.js";
import {DateTime} from "luxon";
import {OAuthTokenWrapper} from "../database/tokens.js";
import {UserController} from "../database/users.js";
import {OIDCScopes} from "../helpers/oidc/scopes.js";

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

        res.redirect("/oidc/auth/grant-scopes")
    }
)

oidcRouter.get(
    "/auth/grant-scopes",
    authMiddleware({
        authRequirement: "require-authenticated",
        redirectTo: "/oidc/auth/grant-scopes"
    }),
    OIDCFlow.middleware(),
    async (req: AuthenticatedRequest & OIDCFlowRequest, res) => {
        const flow = req.oidcFlow!

        const {nonGrantedScopes, grantedScopes} = await flow.checkScopeGrantStatus(req.user!.id)
        const clientController = await OAuthClientController.getByClientId(flow.client_id)
        if (!clientController) {
            return oauthErrorPage(res, "client_id invalid or not found")
        }

        res.render("oauth/scopes.pug", {
            client: clientController.getClient(),
            scopesToGrant: nonGrantedScopes,
            grantedScopes,
        })
    }
)

oidcRouter.get(
    "/auth/grant-scopes-feedback",
    authMiddleware({
        authRequirement: "require-authenticated",
        redirectTo: "/oidc/auth/grant-scopes",
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

        const {nonGrantedScopes} = await flow.checkScopeGrantStatus(req.user!.id)
        await flow.grantScopes(nonGrantedScopes, req.user!.id)

        res.redirect(await flow.successExitURL(req.user!.id))
        flow.end(req)
    }
)

oidcRouter.post(
    "/token",
    async (req, res)  => {
        const { grant_type } = req.body

        if (grant_type === "refresh_token") {
            const { client_id } = req.body
            const oauthClient = await OAuthClientController.getByClientId(client_id)
            if (!oauthClient) {
                res.json({
                    error: "invalid_request",
                    error_description: "Could not find client specified by client_id"
                } as OAuthAccessTokenResponse)
                return
            }

            if (!(await oauthClient.checkClientSecretFromHeaders(req, res))) {
                return
            }

            const { refresh_token } = req.body
            const refreshTokenWrapper = await OAuthTokenWrapper.fromTokenValue(refresh_token)
            if (!refreshTokenWrapper
                || refreshTokenWrapper.data.type !== "Refresh"
                || !refreshTokenWrapper.isRefreshToken
                || !refreshTokenWrapper.isValid
                || !refreshTokenWrapper.belongsToClient(client_id)
            ) {
                res.json({
                    error: "invalid_grant",
                } as OAuthAccessTokenResponse)
                return
            }

            const tm = oauthClient.getTokenManager(refreshTokenWrapper.userId)
            const newAccessToken = await tm.refresh(refreshTokenWrapper)

            res.json({
                access_token: newAccessToken.code,
                token_type: "Bearer",
                expires_in: Math.round(DateTime.fromJSDate(newAccessToken.tokenObject.expires).diffNow().as("seconds")),
            } as OAuthAccessTokenResponse)
        } else if (grant_type === "authorization_code") {
            const { code, redirect_uri } = req.body

            const parsedCode = await AuthorizationCode.parse(code)
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
                return
            }

            const oauthClient = await OAuthClientController.getByClientId(parsedCode.data.clientId)
            if (!oauthClient) {
                res.json({
                    error: "invalid_request",
                    error_description: "Could not find client specified in code"
                } as OAuthAccessTokenResponse)
                return
            }

            if (!(await oauthClient.checkClientSecretFromHeaders(req, res))) return

            const tm = oauthClient.getTokenManager(parsedCode.data.userId)
            let accessToken: string
            let refreshToken: string
            let accessTokenObject: OAuthToken
            try {
                const response = await tm.codeExchange({
                    ...parsedCode.data,
                    originalCode: code,
                })
                accessToken = response.accessToken.code
                accessTokenObject = response.accessToken.tokenObject
                refreshToken = response.refreshToken.code
            } catch (e) {
                console.error(e)
                res.json({
                    error: "invalid_grant",
                } as OAuthAccessTokenResponse)
                return
            }

            const tokenExpiry = DateTime.fromJSDate(accessTokenObject.expires)
            const idToken = await tm.generateIdToken(tokenExpiry, parsedCode.data.nonce)
            res.json({
                access_token: accessToken,
                refresh_token: refreshToken,
                expires_in: Math.round(tokenExpiry.diffNow().as("seconds")),
                token_type: "Bearer",
                id_token: idToken,
            } as OAuthAccessTokenResponse)
        } else {
            res.json({
                error: "unsupported_grant_type",
                error_description: "Only 'authorization_code' and 'refresh_token' are supported",
            } as OAuthAccessTokenResponse)
        }
    }
)

const userInfoHandler = async (req: BearerTokenRequest, res: Response) => {
    const user = await req.tokenWrapper!.mustGetUser()
    res.json(UserController.for(user).toUserInfo(req.tokenWrapper!.hasScope(OIDCScopes.Email)))
}
const openIdScopeMiddleware = OAuthTokenWrapper.middleware([OIDCScopes.Profile])
oidcRouter
    .route("/userinfo")
    .get(openIdScopeMiddleware, userInfoHandler)
    .post(openIdScopeMiddleware, userInfoHandler)

export default oidcRouter