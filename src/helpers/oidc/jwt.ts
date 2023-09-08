import {Duration} from "luxon";
import jwt, {SignOptions} from "jsonwebtoken";
import {getSecretKeys} from "../secretKeys.js";

export class JWTSigner {
    static sign(data: any, duration?: Duration) {
        const opt: SignOptions = {}
        if (duration) {
            opt.expiresIn = duration.as("seconds")
        }
        return jwt.sign(data, getSecretKeys()[0], opt)
    }

    static parse(data: string) {
        try {
            const verifiedToken = jwt.verify(data, getSecretKeys()[0])
            if (typeof verifiedToken === "string") {
                return undefined
            }

            return verifiedToken
        } catch (e) {
            return undefined
        }
    }
}