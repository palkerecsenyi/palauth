import {Duration} from "luxon";
import {JWTSigner} from "./jwt.js";

type AuthorizationCodeData = {
    userId: string,
    clientId: string,
    scope: string
    redirectURI: string
    nonce?: string
}
export type AuthorizationCodeWithOriginal = AuthorizationCodeData & {
    originalCode: string
}

export class AuthorizationCode {
    data: AuthorizationCodeData

    constructor(data: AuthorizationCodeData) {
        this.data = data
    }

    sign() {
        return JWTSigner.sign(this.data, Duration.fromObject({ minute: 10 }))
    }

    static parse(from: string) {
        const verifiedToken = JWTSigner.parse(from)
        if (!verifiedToken) return undefined
        return new AuthorizationCode(verifiedToken as AuthorizationCodeData)
    }
}