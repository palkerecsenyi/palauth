import {JWTSigner} from "./jwt.js";
import {getProjectOIDCID} from "../constants/hostname.js";
import { authorizationCodeDuration } from "../constants/token-duration.js";

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
        return JWTSigner.sign({
            ...this.data,
            iss: getProjectOIDCID(),
        }, authorizationCodeDuration())
    }

    static async parse(from: string) {
        const verifiedToken = await JWTSigner.parse<AuthorizationCodeData>(from, false)
        if (!verifiedToken) return undefined
        return new AuthorizationCode(verifiedToken)
    }
}
