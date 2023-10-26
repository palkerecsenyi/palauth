import express from "express";
import {authMiddleware} from "../helpers/auth.js";
import {AuthenticatedRequest} from "../types/express.js";
import {UserController} from "../database/users.js";
import {OAuthClientController} from "../database/oauth.js";
import bodyParser from "body-parser";
import TwoFactorController from "../helpers/2fa/2fa.js";

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
    "/account/2fa/passkey",
    async (req: AuthenticatedRequest, res) => {
        const twoFaController = await TwoFactorController.mustFromAuthenticatedRequest(req)

        const ready = twoFaController.registrationOfTypeExists("SecurityKey")
        let configured = false

        if (ready) {
            configured = twoFaController.securityKey.isPasskey
        }

        res.render("account/2fa-passkey.pug", {
            ready,
            configured,
        })
    }
)

accountRouter.get(
    "/account/2fa/passkey/enroll",
    async (req: AuthenticatedRequest, res) => {
        const twoFaController = await TwoFactorController.mustFromAuthenticatedRequest(req)
        if (!twoFaController.registrationOfTypeExists("SecurityKey")) {
            req.flash("error", "No security key configured for your account")
        } else if (twoFaController.securityKey.isPasskey) {
            req.flash("error", "You've already configured a passkey")
        } else {
            await twoFaController.securityKey.markAsPasskey()
            req.flash("success", "Passkey configured!")
        }

        res.redirect("/account/2fa/passkey")
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
            const options = await twoFaController.securityKey.generateKeyRegistrationOptions(req)

            res.render("account/2fa-enroll", {
                type,
                options,
            })
        } else if (type === "totp") {
            const secret = await twoFaController.totp.generateSecret(req)
            res.render("account/2fa-enroll", {
                type,
                qrDataUrl: secret.qrCodeUrl,
                rawSecret: secret.rawSecret,
            })
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

            const success = await twoFaController.securityKey.saveKeyRegistration(req)
            if (!success) {
                res.sendStatus(401)
                return
            }
        } else if (type === "totp") {
            if (twoFaController.registrationOfTypeExists("TOTP")) {
                req.flash("error", "You've already enrolled an authenticator app. Please delete it first.")
                res.status(409).redirect("/account/2fa/enroll?type=totp")
                return
            }

            const token = req.body.token
            if (typeof token !== "string") {
                res.status(400).send("No valid token provided")
                return
            }
            const success = await twoFaController.totp.saveRegistration(token, req)

            if (success) {
                req.flash("success", "Added your authenticator app!")
                res.redirect("/account/2fa")
            } else {
                req.flash("error", "Something went wrong. Maybe your code is too old?")
                res.redirect("/account/2fa/enroll?type=totp")
            }
            return
        }

        res.sendStatus(204)
    }
)

export default accountRouter
