import {Duration} from "luxon";
import {JWTSigner} from "./jwt.js";
import {getProjectOIDCID} from "../hostname.js";

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
        }, Duration.fromObject({ minute: 10 }))
    }

    static async parse(from: string) {
        const verifiedToken = await JWTSigner.parse(from)
        if (!verifiedToken) return undefined
        return new AuthorizationCode(verifiedToken as AuthorizationCodeData)
    }
}