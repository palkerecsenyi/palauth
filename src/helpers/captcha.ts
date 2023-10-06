import {NextFunction, Request, Response} from "express";
import {verify} from "hcaptcha"
import {getHCaptchaSecret} from "./constants/secretKeys.js";
import DevModeSettings from "./constants/devMode.js";


export const verifyCaptcha = (failureURL: string | ((req: Request) => string)) => async (req: Request, res: Response, next: NextFunction) => {
    if (DevModeSettings.isCaptchaDisabled()) {
        next()
        return
    }

    const secret = getHCaptchaSecret()
    if (!secret) throw new Error("hcaptcha secret missing")

    let actualFailureURL: string
    if (typeof failureURL === "string") {
        actualFailureURL = failureURL
    } else {
        actualFailureURL = failureURL(req)
    }

    const token = req.body["h-captcha-response"]
    if (typeof token !== "string") {
        res.status(400)
        req.flash("error", "Captcha was missing")
        res.redirect(actualFailureURL)
        return
    }

    const response = await verify(secret, token)
    if (!response.success) {
        res.status(400)
        req.flash("error", "Captcha was invalid")
        res.redirect(actualFailureURL)
        return
    }

    next()
}
