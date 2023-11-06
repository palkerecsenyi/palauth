import express, {Response} from "express";
import {authMiddleware, setProvisionalUserId, setUserId} from "../helpers/auth.js";
import {AuthenticatedRequest, ValidatedRequest} from "../types/express.js";
import {doubleCsrfProtection, generateToken} from "../helpers/csrf.js";
import {DBClient} from "../database/client.js";
import {UserController} from "../database/users.js";
import {FlowManager} from "../helpers/flow.js";
import {verifyCaptcha} from "../helpers/captcha.js";
import {body} from "express-validator"
import {ensureValidators} from "../helpers/validators.js";
import {InviteController} from "../database/invites.js";
import {Prisma, SecondAuthenticationFactorType} from "../database/generated-models/index.js";
import EmailVerificationController from "../helpers/mail/email-verification.js";
import bodyParser from "body-parser";
import DevModeSettings from "../helpers/constants/devMode.js";
import TwoFactorSecurityKeyController from "../helpers/2fa/securityKey.js";

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

authRouter.get(
    "/signin",
    notAuthenticatedMiddleware,
    flowManager.saveDestinationMiddleware.bind(flowManager),
    async (req: AuthenticatedRequest, res) => {
        res.render("auth/signin.pug", {
            csrf: generateToken(req, res),
            keyOptions: await TwoFactorSecurityKeyController.generateKeyAuthenticationOptions(req, []),
        })
    }
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
        const {email, password} = req.validatedData!

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
            req.flash("error", "Please verify your email to continue signing in")
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
    }
)

authRouter.post(
    "/signin/key",
    notAuthenticatedMiddleware,
    flowManager.ensureCanContinue("/auth/signin"),
    bodyParser.json(),
    async (req: AuthenticatedRequest, res) => {
        const user = await TwoFactorSecurityKeyController.identifyKeyAuthentication(req)
        if (!user) {
            res.sendStatus(403)
            return
        }

        setUserId(req, user.id)
        res.sendStatus(204)
    }
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
    }
)

authRouter.get(
    "/signin/2fa/:method",
    provisionalAuthenticatedMiddleware,
    flowManager.ensureCanContinue("/auth/signin"),
    async (req: AuthenticatedRequest, res) => {
        const uc = UserController.for(req.user!)
        const twoFaController = uc.getTwoFactorController()

        const twoFaMethod = req.params["method"] as SecondAuthenticationFactorType
        if (!twoFaController.registrationOfTypeExists(twoFaMethod)) {
            req.flash("error", "Your account isn't registered for that method of 2FA")
            res.redirect("/auth/signin/2fa")
            return
        }

        if (twoFaMethod === "SecurityKey") {
            res.render("auth/2fa-verify.pug", {
                method: twoFaMethod,
                keyOptions: await twoFaController.securityKey.generateKeyAuthenticationOptions(req),
            })
        } else if (twoFaMethod === "TOTP") {
            res.render("auth/2fa-verify.pug", {
                method: twoFaMethod,
            })
        } else {
            res.send("Unimplemented")
        }
    }
)

authRouter.post(
    "/signin/2fa/:method",
    bodyParser.json(),
    provisionalAuthenticatedMiddleware,
    flowManager.ensureCanContinue("/auth/signin"),
    async (req: AuthenticatedRequest, res) => {
        const uc = UserController.for(req.user!)
        const twoFaController = uc.getTwoFactorController()

        const twoFaMethod = req.params["method"] as SecondAuthenticationFactorType
        if (!twoFaController.registrationOfTypeExists(twoFaMethod)) {
            res.sendStatus(204)
            return
        }

        if (twoFaMethod === "SecurityKey") {
            const keyCorrect = await twoFaController.securityKey.checkAndUpdateKeyAuthentication(req)
            if (!keyCorrect) {
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
    }
)

authRouter.get(
    "/continue",
    flowManager.ensureCanContinue("/auth/signin"),
    (req, res) => {
        flowManager.continueToDestination(req, res, "/auth/signin")
    }
)

authRouter.get(
    "/signup",
    flowManager.saveDestinationMiddleware.bind(flowManager),
    async (req, res) => {
        res.render("auth/signup.pug", {
            csrf: generateToken(req, res),
            inviteToken: req.query.invite,
        })
    }
)

authRouter.post(
    "/signup",
    doubleCsrfProtection,
    flowManager.ensureCanContinue("/auth/signup"),
    body("displayName").notEmpty().trim().isLength({ min: 2, max: 20 }),
    body("email").isEmail(),
    (req, res, next) => {
        if (DevModeSettings.isInsecurePasswordsAllowed()) {
            return body("password").notEmpty()(req, res, next)
        }

        body("password").isStrongPassword({
            minLength: 11,
            minNumbers: 1,
        }).withMessage("Must be at least 12 characters with 1 number, 1 uppercase, 1 lowercase, and 1 symbol.")(req, res, next)
    },
    body("passwordConfirm").notEmpty(),
    body("token").notEmpty(),
    ensureValidators("/auth/signup"),
    verifyCaptcha("/auth/signup"),
    async (req: AuthenticatedRequest & ValidatedRequest, res) => {
        const {
            displayName,
            email,
            password,
            passwordConfirm,
            token,
        } = req.validatedData!

        if (password !== passwordConfirm) {
            req.flash("Your two passwords don't match")
            res.redirect("/auth/signup")
            return
        }

        const userId = await DBClient.interruptibleTransaction(async tx => {
            const inviteController = new InviteController(tx)
            const invite = await inviteController.lookupInvite(token)
            if (!invite) {
                req.flash("error", "That invite was not found")
                tx.rollback()
                return
            }

            let userId: string
            try {
                userId = await UserController.createUser({
                    displayName, email, password
                }, DevModeSettings.skipEmailVerification(), tx)
            } catch (e) {
                if (e instanceof Prisma.PrismaClientKnownRequestError && e.meta?.target === "User_email_key") {
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
                const emailVerification = await EmailVerificationController.create(userId, tx)
                await emailVerification.send()
            }

            return userId
        })

        if (!userId) {
            res.redirect("/auth/signup")
            return
        }

        if (DevModeSettings.skipEmailVerification()) {
            req.flash("success", "DEV: skipping email verification, signup complete")
            res.redirect("/auth/signin")
            return
        }

        req.session.signIn = {
            verifyEmail: email,
        }
        res.redirect(`/auth/verify`)
    }
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
    }
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

        const verificationController = await EmailVerificationController.fromEmailAddress(verifyEmail)
        if (!verificationController) {
            req.flash("error", "Can't find which email to resend to")
            res.redirect("/auth/verify")
            return
        }

        await verificationController.send()
        req.flash("success", "Resent the verification email!")
        res.redirect("/auth/verify")
    }
)

authRouter.post(
    "/verify",
    doubleCsrfProtection,
    flowManager.ensureCanContinue("/auth/signin"),
    body("code").notEmpty().trim().isLength({min: 6, max: 6}),
    body("email").notEmpty(),
    ensureValidators("/auth/verify"),
    verifyCaptcha("/auth/verify"),
    async (req, res) => {
        const success = await DBClient.interruptibleTransaction(async tx => {
            const verificationController = await EmailVerificationController.fromRequest(req, tx)
            if (!verificationController) {
                req.flash("error", "That code was not found")
                tx.rollback()
                return false
            }

            await verificationController.markVerified()
            return true
        })

        if (!success) {
            res.redirect("/auth/verify")
            return
        }

        req.flash("success", "Your email was verified! Please sign in to continue.")
        res.redirect("/auth/signin")
    }
)

export default authRouter

export const signOutRoute = (req: AuthenticatedRequest, res: Response) => {
    setUserId(req, undefined)
    res.redirect("/auth/signin?destination=/")
}
