import express, { type NextFunction, type Response, type Request } from "express"
import {
    authMiddleware,
    setProvisionalUserId,
    setUserId,
} from "../helpers/auth.js"
import type { AuthenticatedRequest, ValidatedRequest } from "../types/express.js"
import { doubleCsrfProtection, generateToken } from "../helpers/csrf.js"
import { DBClient } from "../database/client.js"
import { UserController } from "../database/users.js"
import { FlowManager } from "../helpers/flow.js"
import { verifyCaptcha } from "../helpers/captcha.js"
import { body } from "express-validator"
import { ensureValidators } from "../helpers/validators.js"
import { InviteController } from "../database/invites.js"
import type {
    Prisma,
    SecondAuthenticationFactorType,
} from "../database/generated-models/index.js"
import bodyParser from "body-parser"
import DevModeSettings from "../helpers/constants/devMode.js"
import TwoFactorSecurityKeyController from "../helpers/2fa/securityKey.js"
import VerificationMessageController from "../helpers/mail/verification.js"

const authRouter = express.Router()

const notAuthenticatedMiddleware = authMiddleware({
    authRequirement: "require-not-authenticated",
    redirectTo: "/",
    useDestinationQuery: true,
})

const provisionalAuthenticatedMiddleware = authMiddleware({
    authRequirement: "require-provisional-authenticated",
    redirectTo: "/auth/signin",
})

const flowManager = new FlowManager("authentication")

const passwordValidatorMiddleware = (
    req: Request,
    res: Response,
    next: NextFunction,
) => {
    if (DevModeSettings.isInsecurePasswordsAllowed()) {
        return body("password").notEmpty()(req, res, next)
    }

    body("password")
        .isStrongPassword({
            minLength: 11,
            minNumbers: 1,
        })
        .withMessage(
            "Must be at least 12 characters with 1 number, 1 uppercase, 1 lowercase, and 1 symbol.",
        )(req, res, next)
}

authRouter.get(
    "/signin",
    notAuthenticatedMiddleware,
    flowManager.saveDestinationMiddleware.bind(flowManager),
    async (req: AuthenticatedRequest, res) => {
        res.render("auth/signin.pug", {
            csrf: generateToken(req, res),
            keyOptions:
                await TwoFactorSecurityKeyController.generateKeyAuthenticationOptions(
                    req,
                    [],
                    true,
                ),
        })
    },
)

authRouter.post(
    "/signin",
    doubleCsrfProtection,
    notAuthenticatedMiddleware,
    body("email").isEmail(),
    body("password").notEmpty(),
    ensureValidators("/auth/signin"),
    flowManager.ensureCanContinue("/auth/signin"),
    verifyCaptcha("/auth/signin"),
    async (req: AuthenticatedRequest & ValidatedRequest, res) => {
        const { email, password } = req.validatedData!

        const user = await UserController.getByEmail(email)
        if (!user) {
            req.flash("error", "Email or password incorrect")
            res.redirect("/auth/signin")
            return
        }

        if (!user.emailVerified) {
            req.session.signIn = {
                verifyEmail: user.email,
            }
            req.flash(
                "error",
                "Please verify your email to continue signing in",
            )
            res.redirect("/auth/verify")
            return
        }

        const uc = UserController.for(user)
        const passwordCorrect = await uc.checkPassword(password)
        if (!passwordCorrect) {
            req.flash("error", "Email or password incorrect")
            res.redirect("/auth/signin")
            return
        }

        if (uc.requiresTwoFactor) {
            setProvisionalUserId(req, user.id)
            res.redirect("/auth/signin/2fa")
            return
        }

        setUserId(req, user.id)
        flowManager.continueToDestination(req, res, "/auth/signin")
    },
)

authRouter.post(
    "/signin/key",
    notAuthenticatedMiddleware,
    flowManager.ensureCanContinue("/auth/signin"),
    bodyParser.json(),
    async (req: AuthenticatedRequest, res) => {
        try {
            const user =
                await TwoFactorSecurityKeyController.identifyKeyAuthentication(
                    req,
                )
            setUserId(req, user.id)
            res.sendStatus(204)
        } catch (e) {
            console.warn("Passkey: ", e)
            res.sendStatus(403)
        }
    },
)

authRouter.get(
    "/signin/2fa",
    provisionalAuthenticatedMiddleware,
    flowManager.ensureCanContinue("/auth/signin"),
    async (req: AuthenticatedRequest, res) => {
        const uc = UserController.for(req.user!)
        if (!uc.requiresTwoFactor) {
            req.flash("error", "Your account doesn't require 2FA")
            res.redirect("/auth/signin")
            return
        }

        res.render("auth/2fa-method.pug", {
            methods: uc.twoFactorMethods,
        })
    },
)

authRouter.get(
    "/signin/2fa/:method",
    provisionalAuthenticatedMiddleware,
    flowManager.ensureCanContinue("/auth/signin"),
    async (req: AuthenticatedRequest, res) => {
        const uc = UserController.for(req.user!)
        const twoFaController = uc.getTwoFactorController()

        const twoFaMethod = req.params.method as SecondAuthenticationFactorType
        if (!twoFaController.registrationOfTypeExists(twoFaMethod)) {
            req.flash(
                "error",
                "Your account isn't registered for that method of 2FA",
            )
            res.redirect("/auth/signin/2fa")
            return
        }

        if (twoFaMethod === "SecurityKey") {
            res.render("auth/2fa-verify.pug", {
                method: twoFaMethod,
                keyOptions:
                    await twoFaController.securityKey.generateKeyAuthenticationOptions(
                        req,
                        false,
                    ),
            })
        } else if (twoFaMethod === "TOTP") {
            res.render("auth/2fa-verify.pug", {
                method: twoFaMethod,
            })
        } else {
            res.send("Unimplemented")
        }
    },
)

authRouter.post(
    "/signin/2fa/:method",
    bodyParser.json(),
    provisionalAuthenticatedMiddleware,
    flowManager.ensureCanContinue("/auth/signin"),
    async (req: AuthenticatedRequest, res) => {
        const uc = UserController.for(req.user!)
        const twoFaController = uc.getTwoFactorController()

        const twoFaMethod = req.params.method as SecondAuthenticationFactorType
        if (!twoFaController.registrationOfTypeExists(twoFaMethod)) {
            res.sendStatus(204)
            return
        }

        if (twoFaMethod === "SecurityKey") {
            try {
                await twoFaController.securityKey.checkAndUpdateKeyAuthentication(
                    req,
                    false,
                )
            } catch (e) {
                console.warn("2FA SecurityKey: ", e)
                res.sendStatus(403)
                return
            }
        } else if (twoFaMethod === "TOTP") {
            const tokenCorrect = twoFaController.totp.verify(req.body.token)
            if (!tokenCorrect) {
                req.flash("error", "Incorrect token")
                res.redirect("/auth/signin/2fa/TOTP")
                return
            }
        } else {
            res.sendStatus(501)
            return
        }

        setUserId(req, req.user!.id)

        if (twoFaMethod === "SecurityKey") {
            res.sendStatus(204)
        } else {
            res.redirect("/auth/continue")
        }
    },
)

authRouter.get(
    "/continue",
    flowManager.ensureCanContinue("/auth/signin"),
    (req, res) => {
        flowManager.continueToDestination(req, res, "/auth/signin")
    },
)

authRouter.get(
    "/signup",
    flowManager.saveDestinationMiddleware.bind(flowManager),
    async (req, res) => {
        res.render("auth/signup.pug", {
            csrf: generateToken(req, res),
            inviteToken: req.query.invite,
        })
    },
)

authRouter.post(
    "/signup",
    doubleCsrfProtection,
    flowManager.ensureCanContinue("/auth/signup"),
    passwordValidatorMiddleware,
    body("displayName").notEmpty().trim().isLength({ min: 2, max: 20 }),
    body("email").isEmail(),
    body("passwordConfirm").notEmpty(),
    body("token").notEmpty(),
    ensureValidators("/auth/signup"),
    verifyCaptcha("/auth/signup"),
    async (req: AuthenticatedRequest & ValidatedRequest, res) => {
        const { displayName, email, password, passwordConfirm, token } =
            req.validatedData!

        if (password !== passwordConfirm) {
            req.flash("Your two passwords don't match")
            res.redirect("/auth/signup")
            return
        }

        const userId = await DBClient.interruptibleTransaction(async (tx) => {
            const inviteController = new InviteController(tx)
            const invite = await inviteController.lookupInvite(token)
            if (!invite) {
                req.flash("error", "That invite was not found")
                tx.rollback()
                return
            }

            let userId: string
            try {
                userId = await UserController.createUser(
                    {
                        displayName,
                        email,
                        password,
                    },
                    DevModeSettings.skipEmailVerification(),
                    tx,
                )
            } catch (e) {
                if (
                    e instanceof Prisma.PrismaClientKnownRequestError &&
                    e.meta?.target === "User_email_key"
                ) {
                    req.flash("error", "That email address is already in use")
                    tx.rollback()
                    return
                }

                console.error(e)
                req.flash("error", "Something went wrong creating your account")
                tx.rollback()
                return
            }

            if (!DevModeSettings.skipEmailVerification()) {
                try {
                    const emailVerification =
                        await VerificationMessageController.create(
                            userId,
                            "VerifyEmail",
                            tx,
                        )
                    await emailVerification.send()
                } catch (e) {
                    console.error("Sending new user verification email:", e)
                    req.flash(
                        "error",
                        "We failed to send your verification email for some reason. Your account has not been created; please try again.",
                    )
                    tx.rollback()
                    return
                }
            }

            return userId
        })

        if (!userId) {
            res.redirect("/auth/signup")
            return
        }

        if (DevModeSettings.skipEmailVerification()) {
            req.flash(
                "success",
                "DEV: skipping email verification, signup complete",
            )
            res.redirect("/auth/signin")
            return
        }

        req.session.signIn = {
            verifyEmail: email,
        }
        res.redirect("/auth/verify")
    },
)

authRouter.get(
    "/verify",
    flowManager.ensureCanContinue("/auth/signin"),
    (req, res) => {
        const verifyEmail = req.session.signIn?.verifyEmail
        if (!verifyEmail) {
            req.flash("Please sign in to verify your email")
            res.redirect("/auth/signin")
            return
        }

        res.render("auth/verify-email.pug", {
            csrf: generateToken(req, res),
            email: verifyEmail,
        })
    },
)

authRouter.get(
    "/verify/resend",
    flowManager.ensureCanContinue("/auth/signin"),
    async (req, res) => {
        const verifyEmail = req.session.signIn?.verifyEmail
        if (!verifyEmail) {
            res.redirect("/auth/verify")
            return
        }

        const verificationController =
            await VerificationMessageController.fromEmailAddress(
                verifyEmail,
                "VerifyEmail",
            )
        if (!verificationController) {
            req.flash("error", "Can't find which email to resend to")
            res.redirect("/auth/verify")
            return
        }

        await verificationController.send()
        req.flash("success", "Resent the verification email!")
        res.redirect("/auth/verify")
    },
)

authRouter.post(
    "/verify",
    doubleCsrfProtection,
    flowManager.ensureCanContinue("/auth/signin"),
    body("code").notEmpty().trim().isLength({ min: 6, max: 6 }),
    body("email").notEmpty(),
    ensureValidators("/auth/verify"),
    verifyCaptcha("/auth/verify"),
    async (req, res) => {
        const success = await DBClient.interruptibleTransaction(async (tx) => {
            const verificationController =
                await VerificationMessageController.fromRequest(
                    req,
                    "VerifyEmail",
                    tx,
                )
            if (!verificationController) {
                req.flash("error", "That code was not found")
                tx.rollback()
                return false
            }

            await verificationController.delete()
            const user = await UserController.getById(
                verificationController.userId,
                tx,
            )
            await UserController.for(user!).markEmailVerified()
            return true
        })

        if (!success) {
            res.redirect("/auth/verify")
            return
        }

        req.flash(
            "success",
            "Your email was verified! Please sign in to continue.",
        )
        res.redirect("/auth/signin")
    },
)

authRouter.get(
    "/recover",
    flowManager.ensureCanContinue("/auth/signin"),
    (_, res) => {
        res.render("auth/recover.pug")
    },
)

authRouter.get(
    "/recover/:method",
    flowManager.ensureCanContinue("/auth/signin"),
    (req, res) => {
        const method = req.params.method
        if (method === "password") {
            res.render("auth/recover-password.pug", {
                csrf: generateToken(req, res),
            })
        } else {
            res.render("auth/recover-fail.pug")
        }
    },
)

authRouter.post(
    "/recover/password",
    doubleCsrfProtection,
    flowManager.ensureCanContinue("/auth/signin"),
    body("email").isEmail().notEmpty(),
    ensureValidators("/auth/recover/password"),
    verifyCaptcha("/auth/recover/password"),
    async (req: ValidatedRequest, res) => {
        const { email } = req.validatedData!

        res.redirect(`/auth/recover/password/code?email=${email}`)

        await DBClient.interruptibleTransaction(async (tx) => {
            const user = await UserController.getByEmail(email, tx)
            if (!user) return

            const verification = await VerificationMessageController.create(
                user.id,
                "PasswordReset",
                tx,
            )
            await verification.send()
        })
    },
)

authRouter.get(
    "/recover/password/code",
    flowManager.ensureCanContinue("/auth/signin"),
    async (req, res) => {
        const email = req.query.email
        if (typeof email !== "string") {
            res.status(400).send("No email provided")
            return
        }

        res.render("auth/recover-password-code.pug", {
            csrf: generateToken(req, res),
            email: req.query.email,
        })
    },
)

authRouter.post(
    "/recover/password/code",
    doubleCsrfProtection,
    flowManager.ensureCanContinue("/auth/signin"),
    body("email").isEmail().notEmpty(),
    body("code").isLength({ min: 6, max: 6 }),
    passwordValidatorMiddleware,
    body("passwordConfirm").notEmpty(),
    ensureValidators("/auth/recover/password"),
    verifyCaptcha("/auth/recover/password"),
    async (req: ValidatedRequest, res) => {
        const { password, passwordConfirm, email } = req.validatedData!
        if (password !== passwordConfirm) {
            req.flash("error", "Your passwords don't match")
            res.redirect(`/auth/recover/password/code?email=${email}`)
            return
        }

        await DBClient.interruptibleTransaction(async (tx) => {
            const vmc = await VerificationMessageController.fromRequest(
                req,
                "PasswordReset",
                tx,
            )
            if (!vmc) {
                req.flash("error", "Code expired or not recognised")
                res.redirect("/auth/recover/password")
                tx.rollback()
                return
            }

            await vmc.delete()
            const user = await UserController.getById(vmc.userId, tx)
            if (!user) {
                req.flash("error", "Something went wrong")
                res.redirect("/auth/signin")
                tx.rollback()
                return
            }

            const uc = UserController.for(user, tx)
            await uc.updatePassword(password)
        })

        req.flash(
            "success",
            "Updated password successfully! You can sign in now :)",
        )
        res.redirect("/auth/signin")
    },
)

export default authRouter

export const signOutRoute = (req: AuthenticatedRequest, res: Response) => {
    setUserId(req, undefined)
    res.redirect("/auth/signin?destination=/")
}
