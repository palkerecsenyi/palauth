import express, {NextFunction, Response} from "express";
import {authMiddleware} from "../helpers/auth.js";
import {AuthenticatedRequest, ValidatedRequest} from "../types/express.js";
import {OAuthClientController} from "../database/oauth.js";
import {doubleCsrfProtection, generateToken} from "../helpers/csrf.js";
import {body} from "express-validator";
import {ensureValidators} from "../helpers/validators.js";
import {verifyCaptcha} from "../helpers/captcha.js";

const devRouter = express.Router()
devRouter.use(authMiddleware({
    authRequirement: "require-authenticated",
    redirectTo: "/auth/signin?destination=/dev"
}))
devRouter.use(doubleCsrfProtection)

interface OAuthClientRequest extends AuthenticatedRequest {
    oauthClient?: OAuthClientController
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

    req.oauthClient = client
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
    body("usageDescription").trim().isLength({
        min: 10,
        max: 500,
    }),
    ensureValidators(req => `/dev/${req.params.clientId}/edit`),
    resolveClientMiddleware,
    verifyCaptcha(req => `/dev/${req.params.clientId}/edit`),
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
    body("uri").isURL(),
    ensureValidators(req => `/dev/${req.params.clientId}/redirectURIs/add`),
    resolveClientMiddleware,
    verifyCaptcha(req => `/dev/${req.params.clientId}/redirectURIs/add`),
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

export default devRouter