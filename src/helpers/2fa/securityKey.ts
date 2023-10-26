import BaseTwoFactorController from "./general.js"
import { getProjectHostname, getProjectOIDCID } from "../constants/hostname.js"
import { Request } from "express"
import { VerifiedAuthenticationResponse, VerifiedRegistrationResponse, generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server"
import type { AuthenticatorDevice } from "@simplewebauthn/typescript-types"
import { Pick } from "../../database/generated-models/runtime/library.js"
import { SecondAuthenticationFactor } from "../../database/generated-models/index.js"

const rpName = "PalAuth"
const rpID = getProjectHostname()
const rpOrigin = getProjectOIDCID()
type DBAuthenticator = Pick<SecondAuthenticationFactor, "keyPublicKeyId" | "keyCounter" | "keyPublicKey">

export default class TwoFactorSecurityKeyController extends BaseTwoFactorController {
    private static keyRegistrationSessionKey = "2fa_key_reg_challenge"
    private static keyAuthenticationSessionKey = "2fa_key_auth_challenge"
    private get securityKeyFactor() {
        return this.getFactor("SecurityKey")!
    }
    private get allowCredentials() {
        const pkiBase64 = this.securityKeyFactor.keyPublicKeyId
        if (!pkiBase64) {
            return []
        }

        return [{
            type: "public-key" as const,
            id: Buffer.from(pkiBase64, "base64"),
        }]
    }

    private static authenticatorDataToDB(authenticator: AuthenticatorDevice): DBAuthenticator {
        return {
            keyCounter: authenticator.counter,
            keyPublicKeyId: Buffer.from(authenticator.credentialID).toString("base64"),
            keyPublicKey: Buffer.from(authenticator.credentialPublicKey).toString("base64"),
        }
    }
    private static dbToAuthenticatorData(db: DBAuthenticator): AuthenticatorDevice {
        return {
            counter: db.keyCounter!,
            credentialID: Buffer.from(db.keyPublicKeyId!, "base64"),
            credentialPublicKey: Buffer.from(db.keyPublicKey!, "base64"),
        }
    }

    async generateKeyAuthenticationOptions(req: Request) {
        const options = await generateAuthenticationOptions({
            allowCredentials: this.allowCredentials,
        })

        req.session![TwoFactorSecurityKeyController.keyAuthenticationSessionKey] = options.challenge
        return options
    }

    async checkKeyAuthentication(req: Request, clientResponse: any) {
        const clientChallenge = req.session![TwoFactorSecurityKeyController.keyAuthenticationSessionKey]
        if (typeof clientChallenge !== "string") {
            return false
        }

        clientResponse.id = Buffer.from(clientResponse.id).buffer

        let authnResult: VerifiedAuthenticationResponse
        try {
            authnResult = await verifyAuthenticationResponse({
                response: req.body,
                expectedChallenge: clientChallenge,
                expectedOrigin: rpOrigin,
                expectedRPID: rpID,
                authenticator: TwoFactorSecurityKeyController.dbToAuthenticatorData(this.securityKeyFactor),
            })
        } catch (e) {
            console.warn(e)
            return false
        }

        const {verified, authenticationInfo} = authnResult
        if (!verified || !authenticationInfo) {
            return false
        }

        await this.tx.secondAuthenticationFactor.update({
            where: {
                id: this.securityKeyFactor.id,
            },
            data: {
                keyCounter: authenticationInfo.newCounter,
            },
        })

        return true
    }

    async generateKeyRegistrationOptions(req: Request) {
        const options = await generateRegistrationOptions({
            rpName,
            rpID,
            userID: this.user.id,
            userName: this.user.displayName,
            attestationType: "none",
        })

        req.session![TwoFactorSecurityKeyController.keyRegistrationSessionKey] = options.challenge
        return options
    }

    async saveKeyRegistration(req: Request) {
        const clientChallenge = req.session![TwoFactorSecurityKeyController.keyRegistrationSessionKey]
        if (typeof clientChallenge !== "string") {
            return false
        }

        let registrationResult: VerifiedRegistrationResponse
        try {
            registrationResult = await verifyRegistrationResponse({
                response: req.body,
                expectedChallenge: clientChallenge,
                expectedOrigin: rpOrigin,
                expectedRPID: rpID,
            })
        } catch (e) {
            console.warn(e)
            return false
        }

        const {verified, registrationInfo} = registrationResult
        if (!verified || !registrationInfo) {
            return false
        }

        await this.tx.secondAuthenticationFactor.create({
            data: {
                userId: this.user.id,
                type: "SecurityKey",
                ...TwoFactorSecurityKeyController.authenticatorDataToDB(registrationInfo)
            }
        })
        return true
    }
}
