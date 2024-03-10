import { NextFunction, Request, Response } from "express"
import { getCaptchaAPIKey, getCaptchaURL } from "./constants/secretKeys.js"
import DevModeSettings from "./constants/devMode.js"
import axios, { AxiosResponse } from "axios"

export const verifyCaptcha =
    (failureURL: string | ((req: Request) => string)) =>
    async (req: Request, res: Response, next: NextFunction) => {
        if (DevModeSettings.isCaptchaDisabled()) {
            next()
            return
        }

        const secret = getCaptchaAPIKey()
        if (!secret) throw new Error("captcha key missing")

        let actualFailureURL: string
        if (typeof failureURL === "string") {
            actualFailureURL = failureURL
        } else {
            actualFailureURL = failureURL(req)
        }

        const token = req.body["frc-captcha-solution"]
        if (typeof token !== "string") {
            res.status(400)
            req.flash("error", "Captcha was missing")
            res.redirect(actualFailureURL)
            return
        }

        const response = await axios.post<
            { solution: string; secret: string },
            AxiosResponse<{ success: boolean }>
        >(
            `${getCaptchaURL()}/siteverify.php`,
            {
                solution: token,
                secret: getCaptchaAPIKey(),
            },
            {
                validateStatus: (s) => s < 500,
            },
        )

        if (!response.data.success) {
            res.status(400)
            req.flash("error", "Captcha was invalid")
            res.redirect(actualFailureURL)
            return
        }

        next()
    }
