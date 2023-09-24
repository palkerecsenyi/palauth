// @ts-ignore
import {doubleCsrf} from "csrf-csrf";
import {Request} from "express";
import {getSecretKeys} from "./constants/secretKeys.js";

const {
    generateToken,
    doubleCsrfProtection,
} = doubleCsrf({
    getTokenFromRequest(req: Request) {
        return req.body["csrf"]
    },
    getSecret() {
        return getSecretKeys()[0]
    },
    cookieName: "pal_csrf",
})

export {generateToken, doubleCsrfProtection}
