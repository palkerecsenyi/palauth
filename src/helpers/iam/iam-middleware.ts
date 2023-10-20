import { NextFunction, Response } from "express";
import type { IAMRequest, OIDCSecretRequest } from "../../types/express.js";
import IAMController from "../../database/iam.js";

export const iamMiddleware = async (req: OIDCSecretRequest & IAMRequest, res: Response, next: NextFunction) => {
    const occ = req.oauthClient
    if (!occ) {
        return
    }

    const iam = await IAMController.forOAuthClient(occ.getClient().clientId)
    if (!iam) {
        res.status(404).send("IAM not initialised")
        return
    }

    req.iamController = iam
    next()
}
