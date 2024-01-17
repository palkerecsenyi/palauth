import express, {NextFunction, Response} from "express";
import {authMiddleware} from "../helpers/auth.js";
import {AuthenticatedRequest, IAMRequest, ValidatedRequest} from "../types/express.js";
import {OAuthClientController} from "../database/oauth.js";
import {doubleCsrfProtection, generateToken} from "../helpers/csrf.js";
import {body} from "express-validator";
import {ensureValidators} from "../helpers/validators.js";
import {verifyCaptcha} from "../helpers/captcha.js";
import IAMController from "../database/iam.js";
import { DBClient } from "../database/client.js";

const devRouter = express.Router()
devRouter.use(authMiddleware({
    authRequirement: "require-authenticated",
    redirectTo: "/auth/signin?destination=/dev"
}))
devRouter.use(doubleCsrfProtection)

interface OAuthClientRequest extends AuthenticatedRequest {
    oauthClient?: OAuthClientController
    clientId?: string
}

const resolveClientMiddleware = async (req: OAuthClientRequest, res: Response, next: NextFunction) => {
    const clientId = req.params.clientId
    if (!clientId) {
        res.status(400).send("Client ID missing from request")
        return
    }

    const client = await OAuthClientController.getByClientId(req.params.clientId)
    if (!client) {
        res.status(404).send("Client ID not found")
        return
    }

    if (client.getClient().adminId !== req.user!.id) {
        res.status(403).send("This is not your OAuth app")
        return
    }

    req.clientId = clientId
    req.oauthClient = client
    next()
}

const resolveIAMMiddleware = async (req: OAuthClientRequest & IAMRequest, _: Response, next: NextFunction) => {
    const clientId = req.oauthClient!.getClient().clientId
    const iam = await IAMController.forOAuthClient(clientId)
    req.iamController = iam
    next()
}

devRouter.get(
    "/",
    async (req: AuthenticatedRequest, res) => {
        res.render("dev/apps.pug", {
            ownedClients: req.user!.ownedClients,
        })
    }
)

devRouter.get(
    "/register",
    async (req, res) => {
        res.render("dev/register-app.pug", {
            csrf: generateToken(req, res),
        })
    }
)

devRouter.post(
    "/register",
    body("name").trim().isLength({
        min: 2,
        max: 40,
    }),
    body("usageDescription").trim().isLength({
        min: 10,
        max: 500,
    }),
    ensureValidators("/dev/register"),
    verifyCaptcha("/dev/register"),
    async (req: AuthenticatedRequest & ValidatedRequest, res) => {
        const newClient = await OAuthClientController.create({
            name: req.validatedData!.name,
            usageDescription: req.validatedData!.usageDescription,
            adminId: req.user!.id,
        })

        req.flash("success", `Your client secret is: "${newClient.clientSecret}". This is the only time you'll see it!`)
        res.redirect(`/dev/${newClient.clientId}`)
    }
)

devRouter.get(
    "/:clientId",
    resolveClientMiddleware,
    async (req: OAuthClientRequest, res) => {
        res.render("dev/app.pug", {
            client: req.oauthClient!.getClient(),
        })
    }
)

devRouter.get(
    "/:clientId/edit",
    resolveClientMiddleware,
    async (req: OAuthClientRequest, res) => {
        res.render("dev/edit-app.pug", {
            client: req.oauthClient!.getClient(),
            csrf: generateToken(req, res),
        })
    }
)

devRouter.post(
    "/:clientId/update",
    body("usageDescription").isString().trim().isLength({
        min: 10,
        max: 500,
    }),
    ensureValidators(req => `/dev/${req.params.clientId}/edit`),
    verifyCaptcha(req => `/dev/${req.params.clientId}/edit`),
    resolveClientMiddleware,
    async (req: OAuthClientRequest & ValidatedRequest, res) => {
        const { usageDescription } = req.validatedData!
        await req.oauthClient!.update({
            usageDescription,
        })
        req.flash("success", "Usage description saved")
        res.redirect(`/dev/${req.oauthClient!.getClient().clientId}`)
    }
)

devRouter.get(
    "/:clientId/delete",
    resolveClientMiddleware,
    async (req: OAuthClientRequest, res) => {
        await req.oauthClient!.delete()
        req.flash("success", "Successfully deleted your app :(")
        res.redirect("/dev")
    }
)

devRouter.get(
    "/:clientId/redirectURIs/add",
    resolveClientMiddleware,
    async (req: OAuthClientRequest, res) => {
        res.render("dev/add-redirect.pug", {
            client: req.oauthClient!.getClient(),
            csrf: generateToken(req, res),
        })
    }
)

devRouter.post(
    "/:clientId/redirectURIs/create",
    body("uri").isString().trim().isURL({
        require_tld: false,
    }),
    ensureValidators(req => `/dev/${req.params.clientId}/redirectURIs/add`),
    verifyCaptcha(req => `/dev/${req.params.clientId}/redirectURIs/add`),
    resolveClientMiddleware,
    async (req: ValidatedRequest & OAuthClientRequest, res: Response) => {
        const { uri } = req.validatedData!

        await req.oauthClient!.addRedirectURI(uri)
        req.flash("success", "Added new redirect URI")
        res.redirect(`/dev/${req.oauthClient!.getClient().clientId}`)
    }
)

devRouter.get(
    "/:clientId/redirectURIs/:redirectURIId/delete",
    resolveClientMiddleware,
    async (req: OAuthClientRequest, res) => {
        const oauthClient = req.oauthClient!
        const next = () => {
            res.redirect(`/dev/${oauthClient.getClient().clientId}`)
        }

        const { redirectURIId } = req.params
        if (!redirectURIId) {
            req.flash("error", "No redirect URI ID provided")
            return next()
        }

        const matchingRedirect = oauthClient.getClient().redirectURIs.findIndex(e => e.id === redirectURIId)
        if (matchingRedirect === -1) {
            req.flash("error", "Redirect URI not found")
            return next()
        }

        await oauthClient.deleteRedirectURI(redirectURIId)
        req.flash("success", "Successfully deleted redirect")
        next()
    }
)

devRouter.get(
    "/:clientId/iam",
    resolveClientMiddleware,
    async (req: OAuthClientRequest, res) => {
        const iam = await IAMController.forOAuthClient(req.oauthClient!.getClient().clientId)
        res.render("dev/iam/home", {
            client: req.oauthClient!.getClient(),
            roles: iam.listRoles(),
            permissions: await iam.listPermissions(),
            users: await iam.listAllUsersWithRoles(),
        })
    }
)

devRouter.get(
    "/:clientId/iam/permissions/add",
    resolveClientMiddleware,
    async (req: OAuthClientRequest, res) => {
        res.render("dev/iam/add-permission", {
            client: req.oauthClient!.getClient(),
            csrf: generateToken(req, res),
        })
    }
)

devRouter.post(
    "/:clientId/iam/permissions/create",
    body("name").isString().trim().isLength({
        min: 1,
        max: 30
    }).withMessage("Name must be between 1 and 30 characters"),
    ensureValidators(req => `/dev/${req.params.clientId}/iam/permissions/add`),
    verifyCaptcha(req => `/dev/${req.params.clientId}/iam/permissions/add`),
    resolveClientMiddleware,
    resolveIAMMiddleware,
    async (req: OAuthClientRequest & IAMRequest & ValidatedRequest, res) => {
        const { name } = req.validatedData!
        await req.iamController!.createPermission(name)
        req.flash("success", `Permission ${name} created`)
        res.redirect(`/dev/${req.clientId}/iam`)
    }
)

devRouter.get(
    "/:clientId/iam/roles/add",
    resolveClientMiddleware,
    resolveIAMMiddleware,
    async (req: OAuthClientRequest, res) => {
        res.render("dev/iam/add-role", {
            client: req.oauthClient!.getClient(),
            csrf: generateToken(req, res),
        })
    }
)

devRouter.post(
    "/:clientId/iam/roles/create",
    body("name").isString().trim().isLength({
        min: 3,
        max: 30
    }).withMessage("Name must be between 3 and 30 characters"),
    ensureValidators(req => `/dev/${req.params.clientId}/iam/roles/add`),
    verifyCaptcha(req => `/dev/${req.params.clientId}/iam/roles/add`),
    resolveClientMiddleware,
    resolveIAMMiddleware,
    async (req: IAMRequest & OAuthClientRequest & ValidatedRequest, res) => {
        const { name } = req.validatedData!
        await req.iamController!.createRole(name)
        req.flash("success", `Role ${name} created`)
        res.redirect(`/dev/${req.clientId}/iam`)
    }
)

devRouter.get(
    "/:clientId/iam/roles/:roleId/assign",
    resolveClientMiddleware,
    resolveIAMMiddleware,
    async (req: OAuthClientRequest & IAMRequest, res) => {
        const iam = req.iamController!
        res.render("dev/iam/assign-permission-to-role", {
            client: req.oauthClient!.getClient(),
            csrf: generateToken(req, res),
            permissions: await iam.listPermissions(),
            role: iam.getRoleById(req.params.roleId),
        })
    }
)

devRouter.post(
    "/:clientId/iam/roles/:roleId/assign",
    body("permissionId").isString(),
    ensureValidators(req => `/dev/${req.params.clientId}/iam/roles/${req.params.roleId}/assign`),
    verifyCaptcha(req => `/dev/${req.params.clientId}/iam/roles/${req.params.roleId}/assign`),
    resolveClientMiddleware,
    resolveIAMMiddleware,
    async (req: IAMRequest & OAuthClientRequest & ValidatedRequest, res) => {
        const { permissionId } = req.validatedData!
        await req.iamController!.assignPermissionToRole(permissionId, req.params.roleId)
        req.flash("success", "Assigned permission to role")
        res.redirect(`/dev/${req.clientId}/iam`)
    }
)

devRouter.get(
    "/:clientId/iam/roles/:roleId/permission/:permissionId/unassign",
    resolveClientMiddleware,
    resolveIAMMiddleware,
    async (req: IAMRequest & OAuthClientRequest, res) => {
        const { roleId, permissionId } = req.params
        await req.iamController!.unassignPermissionFromRole(permissionId, roleId)
        req.flash("success", "Unassigned permission from role")
        res.redirect(`/dev/${req.clientId}/iam`)
    },
)

devRouter.get(
    "/:clientId/iam/users/assign",
    resolveClientMiddleware,
    resolveIAMMiddleware,
    async (req: IAMRequest & OAuthClientRequest, res) => {
        const iam = req.iamController!
        res.render("dev/iam/assign-role-to-user", {
            csrf: generateToken(req, res),
            client: req.oauthClient!.getClient(),
            roles: iam.listRoles(),
        })
    }
)

devRouter.post(
    "/:clientId/iam/users/assign",
    body("userId").isString(),
    body("roleId").isString(),
    ensureValidators(req => `/dev/${req.params.clientId}/iam/users/assign`),
    verifyCaptcha(req => `/dev/${req.params.clientId}/iam/users/assign`),
    resolveClientMiddleware,
    resolveIAMMiddleware,
    async (req: IAMRequest & OAuthClientRequest & ValidatedRequest, res) => {
        const { userId, roleId } = req.validatedData!
        try {
            await req.iamController!.assignRole({
                userId,
                roleId,
            })
        } catch (e) {
            req.flash("error", DBClient.generateErrorMessage(e))
            res.redirect(`/dev/${req.clientId}/iam/users/assign`)
            return
        }
        req.flash("success", "Assigned role to user")
        res.redirect(`/dev/${req.clientId}/iam`)
    }
)

devRouter.get(
    "/:clientId/iam/users/:userId/roles/:roleId/unassign",
    resolveClientMiddleware,
    resolveIAMMiddleware,
    async (req: IAMRequest & OAuthClientRequest, res) => {
        const { userId, roleId } = req.params
        try {
            await req.iamController!.removeRole({
                userId,
                roleId,
            })
            req.flash("success", "Unassigned role from user")
        } catch (e) {
            req.flash("error", DBClient.generateErrorMessage(e))
        }
        res.redirect(`/dev/${req.clientId}/iam`)
    }
)

export default devRouter
