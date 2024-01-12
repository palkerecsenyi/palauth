import express from "express"
import { authMiddleware } from "../helpers/auth.js"
import groupsManagementMiddleware, { getGroupMiddleware } from "../helpers/groups/groups-middleware.js"
import { GroupRequest, GroupsManagementRequest, ValidatedRequest } from "../types/express.js"
import { body } from "express-validator"
import { ensureValidators } from "../helpers/validators.js"
import { verifyCaptcha } from "../helpers/captcha.js"
import { doubleCsrfProtection, generateToken } from "../helpers/csrf.js"
import { DBClient } from "../database/client.js"

const groupsRouter = express.Router()
groupsRouter.use(authMiddleware({
    authRequirement: "require-authenticated",
    redirectTo: "/auth/signin?destination=/groups",
}))
groupsRouter.use(groupsManagementMiddleware)
groupsRouter.use(doubleCsrfProtection)

groupsRouter.get(
    "/",
    async (req: GroupsManagementRequest, res) => {
        res.render("groups/list.pug", {
            groups: await req.groupsController!.listMyGroups()
        })
    }
)

groupsRouter.get(
    "/add",
    async (req: GroupsManagementRequest, res) => {
        res.render("groups/add.pug", {
            csrf: generateToken(req, res),
        })
    }
)

groupsRouter.post(
    "/create",
    body("systemName").trim().isLength({
        min: 2,
        max: 20,
    }).matches(/^[\w\d-]*$/),
    body("displayName").trim().isLength({
        min: 2,
        max: 40,
    }),
    body("description").trim().isLength({
        max: 200,
    }),
    ensureValidators("/groups/add"),
    verifyCaptcha("/groups/add"),
    async (req: GroupsManagementRequest & ValidatedRequest, res) => {
        const data = req.validatedData!
        try {
            const newId = await req.groupsController!.createGroup({
                systemName: data.systemName,
                displayName: data.displayName,
                description: data.description,
            })
            res.redirect("/groups/" + newId)
        } catch (e) {
            req.flash("error", DBClient.generateErrorMessage(e))
            res.redirect("/groups/add")
        }
    }
)

groupsRouter.get(
    "/:groupId/assign",
    getGroupMiddleware,
    async (req: GroupRequest, res) => {
        res.render("groups/assign.pug", {
            group: req.group!,
            csrf: generateToken(req, res),
        })
    }
)

groupsRouter.post(
    "/:groupId/assign",
    body("userId").isUUID(),
    ensureValidators((r) => `/groups/${r.params.groupId}/assign`),
    verifyCaptcha((r) => `/groups/${r.params.groupId}/assign`),
    async (req: GroupsManagementRequest & ValidatedRequest, res) => {
        const userId = req.validatedData!.userId
        try {
            await req.groupsController!.assignToGroup(
                userId,
                req.params.groupId,
            )
        } catch (e) {
            req.flash("error", DBClient.generateErrorMessage(e))
            res.redirect(`/groups/${req.params.groupId}/assign`)
            return
        }
        res.redirect("/groups")
    }
)

groupsRouter.get(
    "/:groupId/apps",
    async (req: GroupsManagementRequest, res) => {
        res.render("groups/apps-list.pug", {
            group: await req.groupsController!.getGroupForRequest(req),
        })
    }
)

groupsRouter.get(
    "/:groupsId/apps/assign",
    async (req: GroupsManagementRequest, res) => {
        res.render("groups/apps-assign.pug", {
            group: await req.groupsController!.getGroupForRequest(req),
        })
    }
)

groupsRouter.post(
    "/:groupId"
)

export default groupsRouter
