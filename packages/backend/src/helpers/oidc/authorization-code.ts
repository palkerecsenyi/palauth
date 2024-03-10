import { JWTSigner } from "./jwt.js"
import { getProjectOIDCID } from "../constants/hostname.js"
import { authorizationCodeDuration } from "../constants/token-duration.js"

type AuthorizationCodeData = {
    userId: string
    clientId: string
    scope: string
    redirectURI: string
    nonce?: string
    "https://auth.palk.me/isAuthCode": true
}
export type AuthorizationCodeWithOriginal = AuthorizationCodeData & {
    originalCode: string
}

export class AuthorizationCode {
    data: AuthorizationCodeData

    constructor(
        data: Omit<AuthorizationCodeData, "https://auth.palk.me/isAuthCode">,
    ) {
        this.data = {
            ...data,
            "https://auth.palk.me/isAuthCode": true,
        }
    }

    sign() {
        return JWTSigner.sign(
            {
                ...this.data,
                iss: getProjectOIDCID(),
            },
            authorizationCodeDuration(),
        )
    }

    static async parse(from: string) {
        const verifiedToken = await JWTSigner.parse<AuthorizationCodeData>(
            from,
            false,
        )
        if (!verifiedToken) return undefined
        if (verifiedToken["https://auth.palk.me/isAuthCode"] !== true) {
            return undefined
        }
        return new AuthorizationCode(verifiedToken)
    }
}
