import BaseTwoFactorController from "./general.js"
import { getProjectHostname, getProjectOIDCID } from "../constants/hostname.js"
import { Request } from "express"
import { VerifiedAuthenticationResponse, VerifiedRegistrationResponse, generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server"
import type { AuthenticatorDevice, PublicKeyCredentialDescriptorFuture } from "@simplewebauthn/typescript-types"
import { Pick } from "../../database/generated-models/runtime/library.js"
import { SecondAuthenticationFactor } from "../../database/generated-models/index.js"
import { TransactionType } from "../../types/prisma.js"
import { DBClient } from "../../database/client.js"
import TwoFactorController from "./2fa.js"

const rpName = "PalAuth"
const rpID = getProjectHostname()
const rpOrigin = getProjectOIDCID()
type DBAuthenticator = Pick<SecondAuthenticationFactor, "keyPublicKeyId" | "keyCounter" | "keyPublicKey">
const keyStorageEncoding: BufferEncoding = "base64url"

export default class TwoFactorSecurityKeyController extends BaseTwoFactorController {
    private static keyRegistrationSessionKey = "2fa_key_reg_challenge"
    private static keyAuthenticationSessionKey = "2fa_key_auth_challenge"
    private get securityKeyFactor() {
        return this.getFactor("SecurityKey")!
    }
    private get allowCredentials() {
        const encodedKeyId = this.securityKeyFactor.keyPublicKeyId
        if (!encodedKeyId) {
            return []
        }

        return [{
            type: "public-key" as const,
            id: Buffer.from(encodedKeyId, keyStorageEncoding),
        }]
    }

    private static authenticatorDataToDB(authenticator: AuthenticatorDevice): DBAuthenticator {
        return {
            keyCounter: authenticator.counter,
            keyPublicKeyId: Buffer.from(authenticator.credentialID).toString(keyStorageEncoding),
            keyPublicKey: Buffer.from(authenticator.credentialPublicKey).toString(keyStorageEncoding),
        }
    }
    private static dbToAuthenticatorData(db: DBAuthenticator): AuthenticatorDevice {
        return {
            counter: db.keyCounter!,
            credentialID: Buffer.from(db.keyPublicKeyId!, keyStorageEncoding),
            credentialPublicKey: Buffer.from(db.keyPublicKey!, keyStorageEncoding),
        }
    }

    async markAsPasskey() {
        await this.tx.secondAuthenticationFactor.update({
            where: {
                id: this.securityKeyFactor.id,
            },
            data: {
                isPasskey: true,
            }
        })
    }

    get isPasskey() {
        return this.securityKeyFactor.isPasskey === true
    }

    static async generateKeyAuthenticationOptions(req: Request, allowCredentials: PublicKeyCredentialDescriptorFuture[]) {
        const options = await generateAuthenticationOptions({
            allowCredentials: allowCredentials,
            userVerification: "preferred",
            rpID,
        })

        req.session![TwoFactorSecurityKeyController.keyAuthenticationSessionKey] = options.challenge
        return options
    }
    async generateKeyAuthenticationOptions(req: Request) {
        return TwoFactorSecurityKeyController.generateKeyAuthenticationOptions(req, this.allowCredentials)
    }

    static async identifyKeyAuthentication(req: Request, tx: TransactionType = DBClient.getClient()) {
        const id = req.body["id"]
        if (typeof id !== "string") {
            return false
        }

        const factor = await tx.secondAuthenticationFactor.findFirst({
            where: {
                type: "SecurityKey",
                keyPublicKeyId: id,
            },
        })
        if (!factor || !factor.isPasskey) {
            return false
        }

        const controller = await TwoFactorController.fromUserId(factor.userId, tx)
        if (!controller) {
            return false
        }

        const keyAuthenticated = await controller.securityKey.checkAndUpdateKeyAuthentication(req)
        if (!keyAuthenticated) {
            return false
        }

        return controller.getUser()
    }
    async checkAndUpdateKeyAuthentication(req: Request) {
        const clientChallenge = req.session![TwoFactorSecurityKeyController.keyAuthenticationSessionKey]
        if (typeof clientChallenge !== "string") {
            return false
        }

        let authnResult: VerifiedAuthenticationResponse
        try {
            authnResult = await verifyAuthenticationResponse({
                response: req.body,
                expectedChallenge: clientChallenge,
                expectedOrigin: rpOrigin,
                expectedRPID: rpID,
                authenticator: TwoFactorSecurityKeyController.dbToAuthenticatorData(this.securityKeyFactor),
                requireUserVerification: true,
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
            authenticatorSelection: {
                residentKey: "required",
                userVerification: "preferred",
            },
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
                requireUserVerification: true,
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
