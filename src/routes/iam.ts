import express from "express";
import { IAMRequest } from "../types/express.js";
import { oidcSecretMiddleware } from "../helpers/iam/oidc-middleware.js";
import { iamMiddleware } from "../helpers/iam/iam-middleware.js";

const iamRouter = express.Router()

iamRouter.get(
    "/check/*",
    iamMiddleware,
    async (req: IAMRequest, res) => {
        const iam = req.iamController!

        const {userId} = req.query
        if (typeof userId !== "string") {
            res.status(400).send("Missing userId")
            return
        }

        const resourcePathString = req.params[0] as string
        if (!resourcePathString) {
            res.status(400).send("Couldn't parse resource path")
        }

        const resourcePath = resourcePathString.split("/")
        if (resourcePath.length < 2) {
            res.status(400).send("Not enough components in resource path")
        }

        const resourceId = resourcePath[resourcePath.length - 1]
        const scopePath = "/" + resourcePath.slice(0, -1).join("/")

        try {
            const result = await iam.checkResource({
                userId,
                scopePath,
                resourceId,
            })

            res.json({
                scopePath,
                resourceId,
                userId,
                allowed: result,
            })
        } catch (e) {
            res.status(400).send("Failed to check permission")
        }
    }
)

const _r = express.Router()
_r.use("/:clientId", oidcSecretMiddleware, iamRouter)
export default _r
