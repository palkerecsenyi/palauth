import express from "express";
import {authMiddleware} from "../helpers/auth";
import {AuthenticatedRequest} from "../types/express";

const testRouter = express.Router()
testRouter.use(authMiddleware({
    authRequirement: "require-authenticated",
    redirectTo: "/auth/signin?destination=/",
}))

testRouter.get(
    "/",
    async (req: AuthenticatedRequest, res) => {
        res.render("home.pug", {
            user: req.user,
        })
    }
)

export default testRouter