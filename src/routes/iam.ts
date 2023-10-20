import express from "express";
import { IAMRequest } from "../types/express.js";
import { oidcSecretMiddleware } from "../helpers/iam/oidc-middleware.js";
import { iamMiddleware } from "../helpers/iam/iam-middleware.js";
import { parseResourcePathMiddleware } from "../helpers/iam/resource-path.js";

const iamRouter = express.Router()

iamRouter.get(
    "/check/*",
    parseResourcePathMiddleware,
    async (req: IAMRequest, res) => {
        const iam = req.iamController!

        const {userId} = req.query
        if (typeof userId !== "string") {
            res.status(400).send("Missing userId")
            return
        }

        const {scopePath, resourceId} = req.parsedPath!

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

iamRouter.put(
    "/*",
    parseResourcePathMiddleware,
    async (req: IAMRequest, res) => {
        const iam = req.iamController!
        const {scopePath, resourceId} = req.parsedPath!

        try {
            await iam.registerResource({
                scopePath,
                resourceId,
            })
        } catch (e) {
            console.error(e)
            res.status(400).send("Failed to register resource")
            return
        }

        res.sendStatus(204)
    }
)

iamRouter.delete(
    "/*",
    parseResourcePathMiddleware,
    async (req: IAMRequest, res) => {
        const iam = req.iamController!
        const {scopePath, resourceId} = req.parsedPath!
    }
)

const _r = express.Router()
_r.use("/:clientId", oidcSecretMiddleware, iamMiddleware, iamRouter)
export default _r
