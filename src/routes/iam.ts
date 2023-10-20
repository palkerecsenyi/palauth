import express from "express";
import { oidcSecretMiddleware } from "../helpers/iam/oidc-middleware.js";
import { iamMiddleware } from "../helpers/iam/iam-middleware.js";
import { IAMRequest } from "../types/express.js";

const iamRouter = express.Router()
iamRouter.use(oidcSecretMiddleware, iamMiddleware)

iamRouter.get(
    "/check",
    async (req: IAMRequest, res) => {
        const {userId, permission} = req.query
        if (typeof userId !== "string" || typeof permission !== "string") {
            res.status(400).send("No user ID or permission provided")
            return
        }

        const iam = req.iamController!
        res.json({
            allowed: await iam.checkPermission({
                userId, permissionName: permission,
            })
        })
    }
)

export default iamRouter
