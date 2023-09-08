import {Duration} from "luxon";
import jwt, {SignOptions} from "jsonwebtoken";
import {getJWTPrivateKey} from "../secretKeys.js";

export class JWTSigner {
    static sign(data: any, duration?: Duration) {
        const opt: SignOptions = {
            algorithm: "RS256",
        }
        if (duration) {
            opt.expiresIn = duration.as("seconds")
        }
        return jwt.sign(data, getJWTPrivateKey(), opt)
    }

    static parse(data: string) {
        try {
            const verifiedToken = jwt.verify(data, getJWTPrivateKey())
            if (typeof verifiedToken === "string") {
                return undefined
            }

            return verifiedToken
        } catch (e) {
            return undefined
        }
    }
}