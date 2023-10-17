import { Audit, ExpectedAssertionResult, ExpectedAttestationResult, Fido2AssertionResult, Fido2AttestationResult, Fido2Lib } from "fido2-lib"
import BaseTwoFactorController from "./general.js"
import { getProjectHostname, getProjectOIDCID } from "../constants/hostname.js"
import { Request } from "express"

const f2l = new Fido2Lib({
    rpId: getProjectHostname(),
    rpName: "PalAuth",
    challengeSize: 128,
    attestation: "direct",
    authenticatorUserVerification: "preferred",
})

export default class TwoFactorSecurityKeyController extends BaseTwoFactorController {
    private static keyRegistrationSessionKey = "2fa_key_reg_challenge"
    private static keyAuthenticationSessionKey = "2fa_key_auth_challenge"
    private get securityKeyFactor() {
        return this.getFactor("SecurityKey")!
    }
    private get allowCredentials() {
        return [{
            type: "public-key",
            id: this.securityKeyFactor.keyPublicKeyId,
        }]
    }
    private fidoAuditValid(audit: Audit) {
        return audit.complete && audit.validRequest && audit.validExpectations
    }

    async generateKeyAuthenticationOptions(req: Request) {
        const options = await f2l.assertionOptions()
        const encodedChallenge = Buffer.from(options.challenge).toString("base64")
        req.session![TwoFactorSecurityKeyController.keyAuthenticationSessionKey] = encodedChallenge

        return {
            ...options,
            challenge: encodedChallenge,
            allowCredentials: this.allowCredentials,
        }
    }

    async checkKeyAuthentication(req: Request, clientResponse: any) {
        const clientChallenge = req.session![TwoFactorSecurityKeyController.keyAuthenticationSessionKey]
        if (typeof clientChallenge !== "string") {
            return false
        }

        const expectations = {
            challenge: clientChallenge,
            origin: getProjectOIDCID(),
            factor: "second",
            publicKey: this.securityKeyFactor.keyPublicKey!,
            prevCounter: this.securityKeyFactor.keyCounter!,
            userHandle: this.user.id,
        } as ExpectedAssertionResult

        clientResponse.id = Buffer.from(clientResponse.id).buffer

        let authnResult: Fido2AssertionResult
        try {
            authnResult = await f2l.assertionResult(clientResponse, expectations)
        } catch (e) {
            console.warn(e)
            return false
        }

        if (!this.fidoAuditValid(authnResult.audit)) {
            return false
        }

        const counter = authnResult.authnrData.get("counter") as number | undefined
        if (typeof counter !== "number") {
            return false
        }

        await this.tx.secondAuthenticationFactor.update({
            where: {
                id: this.securityKeyFactor.id,
            },
            data: {
                keyCounter: counter,
            },
        })

        return true
    }

    async generateKeyRegistrationOptions(req: Request) {
        const options = await f2l.attestationOptions()
        const encodedChallenge = Buffer.from(options.challenge).toString("base64")
        req.session![TwoFactorSecurityKeyController.keyRegistrationSessionKey] = encodedChallenge
        options.user.id = this.user.id
        options.user.name = this.user.displayName
        options.user.displayName = this.user.displayName
        return {
            ...options,
            challenge: encodedChallenge,
        }
    }

    async saveKeyRegistration(req: Request, clientResponse: any) {
        const clientChallenge = req.session![TwoFactorSecurityKeyController.keyRegistrationSessionKey]
        if (typeof clientChallenge !== "string") {
            return false
        }

        const expectations = {
            challenge: clientChallenge,
            origin: getProjectOIDCID(),
            factor: "second",
        } as ExpectedAttestationResult

        clientResponse.id = Buffer.from(clientResponse.id).buffer

        let registrationResult: Fido2AttestationResult
        try {
            registrationResult = await f2l.attestationResult(clientResponse, expectations)
        } catch (e) {
            console.warn(e)
            return false
        }

        if (!this.fidoAuditValid(registrationResult.audit)) {
            return false
        }

        const counter = registrationResult.authnrData.get("counter") as number | undefined
        const publicKeyPem = registrationResult.authnrData.get("credentialPublicKeyPem") as string | undefined
        const publicKeyId = registrationResult.clientData.get("rawId") as ArrayBuffer | undefined

        if (typeof counter !== "number" || typeof publicKeyPem !== "string" || !(publicKeyId instanceof ArrayBuffer)) {
            return false
        }

        await this.tx.secondAuthenticationFactor.create({
            data: {
                userId: this.user.id,
                type: "SecurityKey",
                keyCounter: counter,
                keyPublicKeyId: Buffer.from(publicKeyId).toString("base64"),
                keyPublicKey: publicKeyPem,
            }
        })
        return true
    }
}
