import express from "express";
import { oidcSecretMiddleware } from "../helpers/iam/oidc-middleware.js";
import { iamMiddleware } from "../helpers/iam/iam-middleware.js";
import { IAMRequest } from "../types/express.js";
import bodyParser from "body-parser";

const iamRouter = express.Router()

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

iamRouter.put(
    "/assign",
    bodyParser.json(),
    async (req: IAMRequest, res) => {
        const {userId, roleName} = req.body
        if (typeof userId !== "string" || typeof roleName !== "string") {
            res.status(400).send("No user ID or role name provided")
            return
        }

        const iam = req.iamController!
        try {
            await iam.assignRoleByName({
                userId, roleName
            })
        } catch (e) {
            res.status(400).send((e as Error).message)
            return
        }

        res.sendStatus(204)
    }
)

const _r = express.Router()
_r.use("/:clientId", oidcSecretMiddleware, iamMiddleware, iamRouter)
export default _r
