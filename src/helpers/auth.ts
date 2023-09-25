import type {NextFunction, Request, Response} from "express";
import {AuthenticatedRequest} from "../types/express.js";
import {UserController} from "../database/users.js";
import {FlowManager} from "./flow.js";

const sessionGetterSetters = (key: string) => {
    return {
        getter(req: Request) {
            if (req.session === undefined || req.session === null) {
                return undefined
            }
            return req.session[key] as string | undefined
        },
        setter(req: Request, value: string | undefined) {
            if (!req.session) return
            if (!value) {
                delete req.session[key]
                return
            }

            req.session[key] = value
        },
    }
}

const {getter: _getUserId, setter: _setUserId} = sessionGetterSetters("userID")
export const getUserId = _getUserId
export const setUserId = (req: Request, value: string | undefined) => {
    _setUserId(req, value)
    setProvisionalUserId(req, undefined)
}
export const {getter: getProvisionalUserId, setter: setProvisionalUserId} = sessionGetterSetters("prov_userID")

type AuthMiddlewareConfig = {
    authRequirement: "none" | "require-not-authenticated" | "require-authenticated" | "require-provisional-authenticated"
    redirectTo?: string
    useDestinationQuery?: boolean
}
export const authMiddleware = (config: AuthMiddlewareConfig) => async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    let actualRedirectTarget = config.redirectTo ?? ""
    if (config.useDestinationQuery) {
        try {
            actualRedirectTarget = FlowManager.parseDestination(req)
        } catch (e) {}
    }

    const userFail = () => {
        setUserId(req, undefined)
        setProvisionalUserId(req, undefined)
        if (config.authRequirement === "require-authenticated") {
            req.flash("error", "Please sign in first")
            res.redirect(actualRedirectTarget)
            return
        }
        next()
    }

    const userId = config.authRequirement === "require-provisional-authenticated" ? getProvisionalUserId(req) : getUserId(req)
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