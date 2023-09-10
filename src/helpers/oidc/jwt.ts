import {DateTime, Duration} from "luxon";
import {getJWKAlg, getJWTPrivateKey, getJWTPublicKey} from "../secretKeys.js";
import * as jose from "jose"
import {getProjectOIDCID} from "../hostname.js";

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

    static async parse(data: string) {
        try {
            const pubKey = await getJWTPublicKey()
            const verifiedToken = await jose.jwtVerify(data, pubKey, {
                issuer: getProjectOIDCID(),
            })

            return verifiedToken.payload
        } catch (e) {
            return undefined
        }
    }
}