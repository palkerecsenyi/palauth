// @ts-ignore
import { doubleCsrf } from "csrf-csrf"
import { Request } from "express"
import { getSecretKey } from "./constants/secretKeys.js"
import DevModeSettings from "./constants/devMode.js"

const { generateToken, doubleCsrfProtection } = doubleCsrf({
    getTokenFromRequest(req: Request) {
        return req.body.csrf
    },
    getSecret() {
        return getSecretKey()
    },
    cookieName: "pal_csrf",
    cookieOptions: {
        sameSite: "strict",
        path: "/",
        secure: !DevModeSettings.isNodeDevMode(),
    },
})

export { generateToken, doubleCsrfProtection }
