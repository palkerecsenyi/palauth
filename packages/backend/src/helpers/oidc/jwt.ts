import { DateTime, type Duration } from "luxon"
import {
    getJWKAlg,
    getJWTPrivateKey,
    getJWTPublicKey,
} from "../constants/secretKeys.js"
import * as jose from "jose"
import { getProjectOIDCID } from "../constants/hostname.js"
import type { IDTokenCustomClaims } from "../../types/oidc.js"

export class JWTSigner {
    static async sign(data: object, duration?: Duration) {
        const privKey = await getJWTPrivateKey()

        const jwt = new jose.SignJWT(data as jose.JWTPayload)
        if (duration) {
            jwt.setExpirationTime(DateTime.now().plus(duration).toUnixInteger())
        }
        jwt.setProtectedHeader({
            alg: getJWKAlg(),
        })
        return jwt.sign(privKey)
    }

    static async parse<
        ExpectedType extends jose.JWTPayload = jose.JWTPayload &
            IDTokenCustomClaims,
    >(data: string, allowExpired = false) {
        try {
            const pubKey = await getJWTPublicKey()
            const verifiedToken = await jose.jwtVerify<ExpectedType>(
                data,
                pubKey,
                {
                    issuer: getProjectOIDCID(),
                },
            )

            if (!allowExpired) {
                const exp = verifiedToken.payload.exp
                if (!exp) {
                    return undefined
                }

                const parsedExp = DateTime.fromSeconds(exp)
                if (parsedExp < DateTime.now()) {
                    // if it's expired, fail
                    return undefined
                }
            }

            return verifiedToken.payload
        } catch (e) {
            return undefined
        }
    }
}
