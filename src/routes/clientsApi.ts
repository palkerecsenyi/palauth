import express from "express";
import { OAuthTokenWrapper } from "../database/tokens.js";
import { OIDCScopes } from "../helpers/oidc/scopes.js";
import { BearerTokenRequest } from "../types/express.js";

const clientsApiRouter = express.Router()

clientsApiRouter.post(
    "/jwt",
    OAuthTokenWrapper.middleware([OIDCScopes.API]),
    async (req: BearerTokenRequest, res) => {
        const tw = req.tokenWrapper!
        res.json(tw.data)
    }
)

export default clientsApiRouter
