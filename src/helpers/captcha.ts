import {NextFunction, Request, Response} from "express";
import {verify} from "hcaptcha"

const secret = process.env["PAL_HCAPTCHA_SECRET"]

export const verifyCaptcha = (failureURL: string) => async (req: Request, res: Response, next: NextFunction) => {
    if (!secret) throw new Error("hcaptcha secret missing")

    const token = req.body["h-captcha-response"]
    if (typeof token !== "string") {
        res.status(400)
        req.flash("error", "Captcha was missing")
        res.redirect(failureURL)
        return
    }

    const response = await verify(secret, token)
    if (!response.success) {
        res.status(400)
        req.flash("error", "Captcha was invalid")
        res.redirect(failureURL)
        return
    }

    next()
}