import type {NextFunction, Request, Response} from "express";
import {AuthenticatedRequest} from "../types/express";
import {UserController} from "../database/users";
import {FlowManager} from "./flow";

export const getUserId = (req: Request) => {
    if (req.session === undefined || req.session === null) {
        return undefined
    }
    return req.session["userID"] as string | undefined
}

export const setUserId = (req: Request, userId: string | undefined) => {
    if (!req.session) return
    if (!userId) {
        delete req.session["userID"]
        return
    }

    req.session["userID"] = userId
}

type AuthMiddlewareConfig = {
    authRequirement: "none" | "require-not-authenticated" | "require-authenticated"
    redirectTo: string
    useDestinationQuery?: boolean
}
export const authMiddleware = (config: AuthMiddlewareConfig) => async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    let actualRedirectTarget = config.redirectTo
    if (config.useDestinationQuery) {
        try {
            actualRedirectTarget = FlowManager.parseDestination(req)
        } catch (e) {}
    }

    const userFail = () => {
        setUserId(req, undefined)
        if (config.authRequirement === "require-authenticated") {
            req.flash("error", "Please sign in first")
            res.redirect(actualRedirectTarget)
            return
        }
        next()
    }

    const userId = getUserId(req)
    if (!userId) {
        userFail()
        return
    }

    const user = await UserController.getById(userId)
    if (!user) {
        userFail()
        return
    }

    if (config.authRequirement === "require-not-authenticated") {
        res.redirect(actualRedirectTarget)
        return
    }

    req.user = user
    next()
}