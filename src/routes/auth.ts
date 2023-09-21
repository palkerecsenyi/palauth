import express, {Response} from "express";
import {authMiddleware, setUserId} from "../helpers/auth.js";
import {AuthenticatedRequest, ValidatedRequest} from "../types/express.js";
import {doubleCsrfProtection, generateToken} from "../helpers/csrf.js";
import {DBClient} from "../database/client.js";
import {UserController} from "../database/users.js";
import {FlowManager} from "../helpers/flow.js";
import {verifyCaptcha} from "../helpers/captcha.js";
import {body} from "express-validator"
import {ensureValidators} from "../helpers/validators.js";
import {InviteController} from "../database/invites.js";
import {Prisma} from "../database/generated-models/index.js";

const authRouter = express.Router()
authRouter.use(authMiddleware({
    authRequirement: "require-not-authenticated",
    redirectTo: "/",
    useDestinationQuery: true,
}))
authRouter.use(doubleCsrfProtection)

const flowManager = new FlowManager("authentication")

authRouter.get(
    "/signin",
    flowManager.saveDestinationMiddleware.bind(flowManager),
    async (req: AuthenticatedRequest, res) => {
        res.render("signin.pug", {
            csrf: generateToken(req, res),
        })
    }
)

authRouter.post(
    "/signin",
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

        const passwordCorrect = await UserController.for(user).checkPassword(password)
        if (!passwordCorrect) {
            req.flash("error", "Email or password incorrect")
            res.redirect("/auth/signin")
            return
        }

        setUserId(req, user.id)
        flowManager.continueToDestination(req, res, "/auth/signin")
    }
)

authRouter.get(
    "/signup",
    flowManager.saveDestinationMiddleware.bind(flowManager),
    async (req, res) => {
        res.render("signup.pug", {
            csrf: generateToken(req, res),
            inviteToken: req.query.invite,
        })
    }
)

authRouter.post(
    "/signup",
    flowManager.ensureCanContinue("/auth/signup"),
    body("displayName").notEmpty().trim().isLength({ min: 2, max: 20 }),
    body("email").isEmail(),
    body("password").isStrongPassword({
        minLength: 12,
        minSymbols: 1,
        minNumbers: 1,
    }).withMessage("Must be at least 12 characters with 1 symbol and 1 number"),
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

            try {
                return await UserController.createUser({
                    displayName, email, password
                })
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
        })

        if (!userId) {
            res.redirect("/auth/signup")
            return
        }

        setUserId(req, userId)
        flowManager.continueToDestination(req, res, "/auth/signup")
    }
)

export default authRouter

export const signOutRoute = (req: AuthenticatedRequest, res: Response) => {
    setUserId(req, undefined)
    res.redirect("/auth/signin?destination=/")
}