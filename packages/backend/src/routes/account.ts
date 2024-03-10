import express from "express"
import { authMiddleware } from "../helpers/auth.js"
import { AuthenticatedRequest } from "../types/express.js"
import { UserController } from "../database/users.js"
import { OAuthClientController } from "../database/oauth.js"
import TwoFactorController from "../helpers/2fa/2fa.js"
import { doubleCsrfProtection, generateToken } from "../helpers/csrf.js"
import { verifyCaptcha } from "../helpers/captcha.js"
import { RegistrationResponseJSON } from "@simplewebauthn/typescript-types"

const accountRouter = express.Router()
accountRouter.use(
    authMiddleware({
        authRequirement: "require-authenticated",
        redirectTo: "/auth/signin?destination=/",
    }),
)

accountRouter.get("/", async (req: AuthenticatedRequest, res) => {
    const uc = UserController.for(req.user!)
    res.render("account/home.pug", {
        user: req.user,
        scopesByClient: uc.scopesByClient(),
        publicClients: await OAuthClientController.getAllPublicClients(),
    })
})

accountRouter.get(
    "/account/revoke-grants/:clientId",
    async (req: AuthenticatedRequest, res) => {
        const clientId = req.params.clientId
        const clientController =
            await OAuthClientController.getByClientId(clientId)
        if (!clientId) {
            req.flash("error", "Client ID not provided in request")
        } else if (!clientController) {
            req.flash("error", "Client ID not found")
        } else {
            const tm = clientController.getTokenManager(req.user!.id)
            await tm.revokeAllAccess()

            req.flash(
                "success",
                `Access revoked for ${clientController.getClient().name}`,
            )
        }

        res.redirect("/")
    },
)

accountRouter.get("/account/2fa", async (req: AuthenticatedRequest, res) => {
    const twoFaController =
        await TwoFactorController.mustFromAuthenticatedRequest(req)

    res.render("account/2fa.pug", {
        factors: twoFaController.factors,
        factorTypes: twoFaController.factors.map((e) => e.type),
    })
})

accountRouter.get(
    "/account/2fa/passkey-question",
    async (_: AuthenticatedRequest, res) => {
        res.render("account/2fa-passkey-question.pug")
    },
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

        const twoFaController =
            await TwoFactorController.mustFromAuthenticatedRequest(req)

        if (type === "key") {
            const passkey = req.query.passkey === "yes"

            const options =
                await twoFaController.securityKey.generateKeyRegistrationOptions(
                    req,
                    passkey,
                )
            res.render("account/2fa-enroll", {
                type,
                options,
                passkey,
                csrf: generateToken(req, res),
            })
        } else if (type === "totp") {
            const secret = await twoFaController.totp.generateSecret(req)
            res.render("account/2fa-enroll", {
                type,
                qrDataUrl: secret.qrCodeUrl,
                rawSecret: secret.rawSecret,
                csrf: generateToken(req, res),
            })
        }
    },
)

accountRouter.post(
    "/account/2fa/enroll",
    verifyCaptcha("/account/2fa"),
    doubleCsrfProtection,
    async (req: AuthenticatedRequest, res) => {
        const { type } = req.query
        if (type !== "key" && type !== "totp") {
            res.sendStatus(400)
            return
        }

        const twoFaController =
            await TwoFactorController.mustFromAuthenticatedRequest(req)

        if (type === "key") {
            const keyDataB64 = req.body.key
            const keyDataString = Buffer.from(keyDataB64, "base64").toString(
                "utf8",
            )
            let parsedKeyData: object
            try {
                parsedKeyData = JSON.parse(keyDataString)
            } catch (e) {
                req.flash("error", "No key data provided")
                res.redirect("/account/2fa/enroll?type=key")
                return
            }

            const nickname = req.body.name
            if (typeof nickname !== "string") {
                req.flash("error", "No nickname provided")
                res.redirect("/account/2fa/enroll?type=key")
                return
            }
            if (nickname.length < 3 || nickname.length > 100) {
                req.flash(
                    "error",
                    "Nickname must be between 3 and 100 characters",
                )
                res.redirect("/account/2fa/enroll?type=key")
                return
            }

            const passkey = req.body.passkey === "yes"
            const success =
                await twoFaController.securityKey.saveKeyRegistration(
                    req,
                    parsedKeyData as RegistrationResponseJSON,
                    nickname,
                    passkey,
                )
            if (!success) {
                req.flash(
                    "error",
                    "Failed to enroll your key. Please try again.",
                )
                res.redirect("/account/2fa/enroll?type=key")
                return
            }

            req.flash("success", `Added your key with nickname ${nickname}`)
            res.redirect("/account/2fa")
        } else if (type === "totp") {
            if (twoFaController.registrationOfTypeExists("TOTP")) {
                req.flash(
                    "error",
                    "You've already enrolled an authenticator app. Please delete it first.",
                )
                res.redirect("/account/2fa/enroll?type=totp")
                return
            }

            const token = req.body.token
            if (typeof token !== "string") {
                req.flash("error", "No valid token provided")
                res.redirect("/account/2fa/enroll?type=totp")
                return
            }
            const success = await twoFaController.totp.saveRegistration(
                token,
                req,
            )

            if (success) {
                req.flash("success", "Added your authenticator app!")
                res.redirect("/account/2fa")
            } else {
                req.flash(
                    "error",
                    "Something went wrong. Maybe your code is too old?",
                )
                res.redirect("/account/2fa/enroll?type=totp")
            }
            return
        }
    },
)

accountRouter.get(
    "/account/2fa/unenroll/:factorID",
    async (req: AuthenticatedRequest, res) => {
        const { factorID } = req.params
        if (!factorID) {
            req.flash("error", "No factor ID provided")
        } else {
            const twoFaController =
                await TwoFactorController.mustFromAuthenticatedRequest(req)
            const matchingFactor = twoFaController.factors.find(
                (f) => f.id === factorID,
            )
            if (!matchingFactor) {
                req.flash("error", "Factor ID not found")
            } else {
                await twoFaController.deleteFactor(matchingFactor.id)
                req.flash("success", "Deleted your authentication factor")
            }
        }

        res.redirect("/account/2fa")
    },
)

export default accountRouter
