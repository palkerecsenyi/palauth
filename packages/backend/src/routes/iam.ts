import express, { type Response } from "express"
import { oidcSecretMiddleware } from "../helpers/iam/oidc-middleware.js"
import { iamMiddleware } from "../helpers/iam/iam-middleware.js"
import type { IAMRequest } from "../types/express.js"
import bodyParser from "body-parser"

const iamRouter = express.Router()

iamRouter.get("/roles", (req: IAMRequest, res) => {
    const iam = req.iamController!
    res.json(iam.listRoles())
})

iamRouter.get("/roles/:userId", async (req: IAMRequest, res) => {
    const { userId } = req.params
    if (!userId) {
        res.status(400).send("User ID not provided")
        return
    }

    const iam = req.iamController!
    const roles = await iam.listRolesForUser(userId)
    res.json({
        userId,
        roles,
    })
})

iamRouter.get("/check", async (req: IAMRequest, res) => {
    const { userId, permission } = req.query
    if (typeof userId !== "string" || typeof permission !== "string") {
        res.status(400).send("No user ID or permission provided")
        return
    }

    const iam = req.iamController!
    res.json({
        allowed: await iam.checkPermission({
            userId,
            permissionName: permission,
        }),
    })
})

const assignmentRouteHandler = async (req: IAMRequest, res: Response) => {
    const { userId, roleName } = req.body
    if (typeof userId !== "string" || typeof roleName !== "string") {
        res.status(400).send("No user ID or role name provided")
        return
    }

    const iam = req.iamController!
    try {
        if (req.method === "PUT") {
            await iam.assignRole({
                userId,
                roleName,
            })
        } else if (req.method === "DELETE") {
            await iam.removeRole({
                userId,
                roleName,
            })
        }
    } catch (e) {
        res.status(400).send((e as Error).message)
        return
    }

    res.sendStatus(204)
}
iamRouter
    .route("/assignment")
    .put(bodyParser.json(), assignmentRouteHandler)
    .delete(bodyParser.json(), assignmentRouteHandler)

const _r = express.Router()
_r.use("/:clientId", oidcSecretMiddleware, iamMiddleware, iamRouter)
export default _r
