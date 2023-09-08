import express from "express";
import {authMiddleware} from "../helpers/auth.ts";
import {AuthenticatedRequest} from "../types/express.ts";
import {doubleCsrfProtection} from "../helpers/csrf.js";

const testRouter = express.Router()
testRouter.use(authMiddleware({
    authRequirement: "require-authenticated",
    redirectTo: "/auth/signin?destination=/",
}))
testRouter.use(doubleCsrfProtection)

testRouter.get(
    "/",
    async (req: AuthenticatedRequest, res) => {
        res.render("home.pug", {
            user: req.user,
        })
    }
)

export default testRouter