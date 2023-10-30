import {DateTime, Duration} from "luxon";
import {getJWKAlg, getJWTPrivateKey, getJWTPublicKey} from "../constants/secretKeys.js";
import * as jose from "jose"
import {getProjectOIDCID} from "../constants/hostname.js";

export class JWTSigner {
    static async sign(data: any, duration?: Duration) {
        const privKey = await getJWTPrivateKey()

        const jwt = new jose.SignJWT(data)
        if (duration) {
            jwt.setExpirationTime(DateTime.now().plus(duration).toUnixInteger())
        }
        jwt.setProtectedHeader({
            alg: getJWKAlg()
        })
        return jwt.sign(privKey)
    }

    static async parse(data: string, requireExpiration = false) {
        try {
            const pubKey = await getJWTPublicKey()
            const verifiedToken = await jose.jwtVerify(data, pubKey, {
                issuer: getProjectOIDCID(),
            })

            const exp = verifiedToken.payload.exp
            if (exp !== undefined) {
                const parsedExp = DateTime.fromSeconds(exp)
                if (parsedExp < DateTime.now()) {
                    // if it's expired, fail
                    return undefined
                }
            } else if (requireExpiration) {
                // no exp provided, so we fail!
                return undefined
            }

            return verifiedToken.payload
        } catch (e) {
            return undefined
        }
    }
}
