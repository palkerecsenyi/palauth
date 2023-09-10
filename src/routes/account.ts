import express from "express";
import {authMiddleware} from "../helpers/auth.js";
import {AuthenticatedRequest} from "../types/express.js";
import {doubleCsrfProtection} from "../helpers/csrf.js";
import {UserController} from "../database/users.js";
import {OAuthClientController} from "../database/oauth.js";

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

export default accountRouter