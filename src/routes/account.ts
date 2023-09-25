import express from "express";
import {authMiddleware} from "../helpers/auth.js";
import {AuthenticatedRequest} from "../types/express.js";
import {doubleCsrfProtection} from "../helpers/csrf.js";
import {UserController} from "../database/users.js";
import {OAuthClientController} from "../database/oauth.js";
import TwoFactorController from "../helpers/2fa.js";
import bodyParser from "body-parser";
import {DBClient} from "../database/client.js";

const accountRouter = express.Router()
accountRouter.use(authMiddleware({
    authRequirement: "require-authenticated",
    redirectTo: "/auth/signin?destination=/",
}))

accountRouter.get(
    "/",
    async (req: AuthenticatedRequest, res) => {
        const uc = UserController.for(req.user!)
        res.render("account/home.pug", {
            user: req.user,
            scopesByClient: uc.scopesByClient(),
        })
    }
)

accountRouter.get(
    "/account/revoke-grants/:clientId",
    async (req: AuthenticatedRequest, res) => {
        const clientId = req.params["clientId"]
        const clientController = await OAuthClientController.getByClientId(clientId)
        if (!clientId) {
            req.flash("error", "Client ID not provided in request")
        } else if (!clientController) {
            req.flash("error", "Client ID not found")
        } else {
            const tm = clientController.getTokenManager(req.user!.id)
            await tm.revokeAllAccess()

            req.flash("success", `Access revoked for ${clientController.getClient().name}`)
        }

        res.redirect("/")
    }
)

accountRouter.get(
    "/account/2fa",
    async (req: AuthenticatedRequest, res) => {
        const twoFaController = await TwoFactorController.mustFromAuthenticatedRequest(req)

        res.render("account/2fa.pug", {
            factors: twoFaController.factors,
            factorTypes: twoFaController.factors.map(e => e.type),
        })
    }
)

accountRouter.get(
    "/account/2fa/enroll",
    async (req: AuthenticatedRequest, res) => {
        const { type } = req.query
        if (type !== "key" && type !== "totp") {
            req.flash("error", "That enrollment type was not recognised")
            res.redirect("/account/2fa")
            return
        }

        const twoFaController = await TwoFactorController.mustFromAuthenticatedRequest(req)

        if (type === "key") {
            const options = await twoFaController.generateKeyRegistrationOptions(req)

            res.render("account/2fa-enroll", {
                type,
                options,
            })
        } else {
            res.send("Unimplemented")
        }
    }
)

accountRouter.post(
    "/account/2fa/enroll",
    bodyParser.json(),
    async (req: AuthenticatedRequest, res) => {
        const { type } = req.query
        if (type !== "key" && type !== "totp") {
            res.sendStatus(400)
            return
        }

        const twoFaController = await TwoFactorController.mustFromAuthenticatedRequest(req)

        if (type === "key") {
            if (twoFaController.registrationOfTypeExists("SecurityKey")) {
                res.sendStatus(409)
                return
            }

            const success = await twoFaController.saveKeyRegistration(req, req.body)
            if (!success) {
                res.sendStatus(401)
                return
            }
        }

        res.sendStatus(204)
    }
)

export default accountRouter