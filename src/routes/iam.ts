import express, { Response } from "express";
import { IAMRequest } from "../types/express.js";
import { oidcSecretMiddleware } from "../helpers/iam/oidc-middleware.js";
import { iamMiddleware } from "../helpers/iam/iam-middleware.js";
import { parseResourcePathMiddleware } from "../helpers/iam/resource-path.js";
import bodyParser from "body-parser";

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

const handleAccessCreateDelete = async (req: IAMRequest, res: Response) => {
    const iam = req.iamController!
    const {scopePath, resourceId} = req.parsedPath!

    const {userId} = req.body
    try {
        await iam.grant(
            {
                scopePath, resourceId,
                userId,
            },
            req.method === "PUT" ? "grant" : "delete"
        )
    } catch (e) {
        console.error(e)
        res.status(400).send("Failed to grant/delete access")
        return
    }

    res.sendStatus(204)
}
iamRouter.route("/access/*")
    .put(parseResourcePathMiddleware, bodyParser.json(), handleAccessCreateDelete)
    .delete(parseResourcePathMiddleware, bodyParser.json(), handleAccessCreateDelete)

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

        try {
            await iam.deleteResource({
                scopePath, resourceId
            })
        } catch (e) {
            console.error(e)
            res.status(400).send("Failed to delete resource")
            return
        }

        res.sendStatus(204)
    }
)

const _r = express.Router()
_r.use("/:clientId", oidcSecretMiddleware, iamMiddleware, iamRouter)
export default _r
