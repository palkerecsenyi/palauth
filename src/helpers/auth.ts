import type {NextFunction, Request, Response} from "express";
import {AuthenticatedRequest} from "../types/express";
import {UserController} from "../database/users";

export const getUserId = (req: Request) => {
    if (req.session === undefined || req.session === null) {
        return undefined
    }
    return req.session["userID"] as string | undefined
}

export const setUserId = (req: Request, userId: string | undefined) => {
    if (!req.session) return
    req.session["userID"] = userId
}

type AuthMiddlewareConfig = {
    authRequirement: "none" | "require-not-authenticated" | "require-authenticated"
    redirectTo: string
}
export const authMiddleware = (config: AuthMiddlewareConfig) => async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const userId = getUserId(req)
    if (!userId) {
        if (config.authRequirement === "require-authenticated") {
            res.redirect(config.redirectTo)
            return
        }
        next()
        return
    }

    const user = await UserController.getById(userId)
    if (!user) {
        setUserId(req, undefined)
        if (config.authRequirement === "require-authenticated") {
            res.redirect(config.redirectTo)
            return
        }
        next()
        return
    }

    if (config.authRequirement === "require-not-authenticated") {
        res.redirect(config.redirectTo)
        return
    }

    req.user = user
    next()
}