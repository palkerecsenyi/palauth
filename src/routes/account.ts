import express from "express";
import {authMiddleware} from "../helpers/auth.js";
import {AuthenticatedRequest, ValidatedRequest} from "../types/express.js";
import {UserController} from "../database/users.js";
import {OAuthClientController} from "../database/oauth.js";
import TwoFactorController from "../helpers/2fa/2fa.js";
import { generateToken } from "../helpers/csrf.js";
import { body } from "express-validator";
import { ensureValidators } from "../helpers/validators.js";

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
            publicClients: await OAuthClientController.getAllPublicClients(),
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
            configured = twoFaController.securityKey.hasPasskey
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
        } else if (twoFaController.securityKey.hasPasskey) {
            req.flash("error", "You've already configured a passkey")
        } else {
            // TODO: configure this lol
            await twoFaController.securityKey.markAsPasskey("")
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
                csrf: generateToken(req, res),
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
    body("name").isString().isLength({min: 3, max: 50}),
    ensureValidators("/account/2fa/enroll?type=key"),
    async (req: AuthenticatedRequest & ValidatedRequest, res) => {
        const { type } = req.query
        if (type !== "key" && type !== "totp") {
            res.sendStatus(400)
            return
        }

        const twoFaController = await TwoFactorController.mustFromAuthenticatedRequest(req)

        if (type === "key") {
            const keyDataB64 = req.body.key
            const keyDataString = Buffer.from(keyDataB64, "base64").toString("utf8")
            let parsedKeyData: any
            try {
                parsedKeyData = JSON.parse(keyDataString)
            } catch (e) {
                req.flash("error", "No key data provided")
                return
            }

            const nickname = req.validatedData!.name
            if (typeof nickname !== "string") {
                req.flash("error", "No nickname provided")
                return
            }

            const success = await twoFaController.securityKey.saveKeyRegistration(req, parsedKeyData, nickname)
            if (!success) {
                req.flash("error", "Failed to enroll your key. Please try again.")
                return
            }

            req.flash("success", "Added your key with nickname " + nickname)
            res.redirect("/account/2fa")
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
    }
)

export default accountRouter
