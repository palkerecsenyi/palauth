import express from "express";
import {authMiddleware} from "../helpers/auth.js";
import {AuthenticatedRequest} from "../types/express.js";
import {doubleCsrfProtection} from "../helpers/csrf.js";
import {UserController} from "../database/users.js";

const accountRouter = express.Router()
accountRouter.use(authMiddleware({
    authRequirement: "require-authenticated",
    redirectTo: "/auth/signin?destination=/",
}))
accountRouter.use(doubleCsrfProtection)

accountRouter.get(
    "/",
    async (req: AuthenticatedRequest, res) => {
        const uc = UserController.for(req.user!)
        res.render("home.pug", {
            user: req.user,
            scopesByClient: uc.scopesByClient(),
        })
    }
)

export default accountRouter