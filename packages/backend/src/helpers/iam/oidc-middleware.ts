import type { NextFunction, Response } from "express"
import type { OIDCSecretRequest } from "../../types/express.js"
import { OAuthClientController } from "../../database/oauth.js"

export const oidcSecretMiddleware = async (
    req: OIDCSecretRequest,
    res: Response,
    next: NextFunction,
) => {
    const clientId = req.params.clientId
    if (typeof clientId !== "string") {
        res.status(403).send("client ID not provided")
        return
    }

    const oauthClient = await OAuthClientController.getByClientId(clientId)
    if (!oauthClient) {
        res.status(403).send("client id not found")
        return
    }

    if (!(await oauthClient.checkClientSecretFromHeaders(req, res))) return

    req.oauthClient = oauthClient
    next()
}
