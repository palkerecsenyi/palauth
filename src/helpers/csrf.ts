// @ts-ignore
import {doubleCsrf} from "csrf-csrf";
import {Request} from "express";
import {getSecretKeys} from "./secretKeys.ts";

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
})

export {generateToken, doubleCsrfProtection}
