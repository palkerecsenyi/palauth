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
    private get securityKeyFactors() {
        return this.getFactors("SecurityKey")
    }
    private get allowCredentials() {
        return this.securityKeyFactors.map(f => {
            const encodedKeyId = f.keyPublicKeyId
            if (!encodedKeyId) {
                return []
            }

            return {
                type: "public-key" as const,
                id: Buffer.from(encodedKeyId, keyStorageEncoding),
            }
        }) as PublicKeyCredentialDescriptorFuture[]
    }

    private static ui8aToString(clientId: Uint8Array) {
        return Buffer.from(clientId).toString(keyStorageEncoding)
    }

    private static authenticatorDataToDB(authenticator: AuthenticatorDevice): DBAuthenticator {
        return {
            keyCounter: authenticator.counter,
            keyPublicKeyId: TwoFactorSecurityKeyController.ui8aToString(authenticator.credentialID),
            keyPublicKey: TwoFactorSecurityKeyController.ui8aToString(authenticator.credentialPublicKey),
        }
    }
    private static dbToAuthenticatorData(db: DBAuthenticator): AuthenticatorDevice {
        return {
            counter: db.keyCounter!,
            credentialID: Buffer.from(db.keyPublicKeyId!, keyStorageEncoding),
            credentialPublicKey: Buffer.from(db.keyPublicKey!, keyStorageEncoding),
        }
    }

    async markAsPasskey(factorId: string) {
        if (!this.securityKeyFactors.some(e => e.id === factorId)) {
            throw new Error("User does not have factor with that ID")
        }

        await this.tx.secondAuthenticationFactor.update({
            where: {
                id: factorId,
            },
            data: {
                isPasskey: true,
            }
        })
    }

    get hasPasskey() {
        return this.securityKeyFactors.some(e => e.isPasskey)
    }

    static async generateKeyAuthenticationOptions(req: Request, allowCredentials: PublicKeyCredentialDescriptorFuture[]) {
        const options = await generateAuthenticationOptions({
            allowCredentials: allowCredentials,
            userVerification: "preferred",
            rpID,
        })

        req.session.twoFactor = {
            securityKey: {
                currentChallenge: options.challenge,
                challengeType: "authentication",
            }
        }
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
        const clientChallenge = req.session.twoFactor?.securityKey?.currentChallenge
        if (
            typeof clientChallenge !== "string" 
            || req.session.twoFactor?.securityKey?.challengeType !== "authentication"
        ) {
            return false
        }

        const matchingKey = this.securityKeyFactors.find(f => f.keyPublicKeyId === req.body["id"])
        if (!matchingKey) {
            return false
        }

        let authnResult: VerifiedAuthenticationResponse
        try {
            authnResult = await verifyAuthenticationResponse({
                response: req.body,
                expectedChallenge: clientChallenge,
                expectedOrigin: rpOrigin,
                expectedRPID: rpID,
                authenticator: TwoFactorSecurityKeyController.dbToAuthenticatorData(matchingKey),
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
                id: matchingKey.id,
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
            supportedAlgorithmIDs: [-7, -257],
        })

        req.session.twoFactor = {
            securityKey: {
                currentChallenge: options.challenge,
                challengeType: "registration",
            }
        }
        return options
    }

    async saveKeyRegistration(req: Request, keyData: any, nickname: string) {
        const clientChallenge = req.session.twoFactor?.securityKey?.currentChallenge
        if (
            typeof clientChallenge !== "string"
            || req.session.twoFactor?.securityKey?.challengeType !== "registration"
        ) {
            return false
        }

        let registrationResult: VerifiedRegistrationResponse
        try {
            registrationResult = await verifyRegistrationResponse({
                response: keyData,
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

        const dbAuthenticatorData = TwoFactorSecurityKeyController.authenticatorDataToDB(registrationInfo)
        if (dbAuthenticatorData.keyPublicKeyId === null) {
            throw new TypeError("keyPublicKeyId should not have been null")
        }

        const existingRegistration = this.securityKeyFactors.find(f => f.keyPublicKeyId === dbAuthenticatorData.keyPublicKeyId)
        if (existingRegistration) {
            return false
        }

        await this.tx.secondAuthenticationFactor.create({
            data: {
                userId: this.user.id,
                type: "SecurityKey",
                ...dbAuthenticatorData,
                keyNickname: nickname,
            }
        })
        return true
    }
}
