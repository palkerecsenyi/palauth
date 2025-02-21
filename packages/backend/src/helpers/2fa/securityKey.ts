import BaseTwoFactorController from "./general.js"
import { getProjectHostname, getProjectOIDCID } from "../constants/hostname.js"
import type { Request } from "express"
import {
    type AuthenticatorTransportFuture,
    type Base64URLString,
    type VerifiedRegistrationResponse,
    type WebAuthnCredential,
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
} from "@simplewebauthn/server"
import type {
    RegistrationResponseJSON,
} from "@simplewebauthn/typescript-types"
import type { Pick } from "../../database/generated-models/runtime/library.js"
import type { SecondAuthenticationFactor } from "../../database/generated-models/index.js"
import type { TransactionType } from "../../types/prisma.js"
import { DBClient } from "../../database/client.js"
import TwoFactorController from "./2fa.js"

const rpName = "PalAuth"
const rpID = getProjectHostname()
const rpOrigin = getProjectOIDCID()
type DBAuthenticator = Pick<
    SecondAuthenticationFactor,
    "keyPublicKeyId" | "keyCounter" | "keyPublicKey"
>
type AllowedCredential = {
    id: Base64URLString
    transports?: AuthenticatorTransportFuture[]
}
const keyStorageEncoding: BufferEncoding = "base64url"

export default class TwoFactorSecurityKeyController extends BaseTwoFactorController {
    private get securityKeyFactors() {
        return this.getFactors("SecurityKey")
    }
    private get allowCredentials() {
        return this.securityKeyFactors
            .map((f) => f.keyPublicKeyId)
            .filter((id) => !!id)
            .map((id) => {
                return {
                    id,
                } as AllowedCredential
            })
    }

    private static ui8aToString(clientId: Uint8Array) {
        return Buffer.from(clientId).toString(keyStorageEncoding)
    }

    private static credentialToDB(
        credential: WebAuthnCredential,
    ): DBAuthenticator {
        return {
            keyCounter: credential.counter,
            keyPublicKeyId: credential.id,
            keyPublicKey: TwoFactorSecurityKeyController.ui8aToString(
                credential.publicKey,
            ),
        }
    }
    private static dbToCredential(db: DBAuthenticator): WebAuthnCredential {
        return {
            counter: db.keyCounter!,
            id: db.keyPublicKeyId!,
            publicKey: Buffer.from(db.keyPublicKey!, keyStorageEncoding),
        }
    }

    async markAsPasskey(factorId: string) {
        if (!this.securityKeyFactors.some((e) => e.id === factorId)) {
            throw new Error("User does not have factor with that ID")
        }

        await this.tx.secondAuthenticationFactor.update({
            where: {
                id: factorId,
            },
            data: {
                isPasskey: true,
            },
        })
    }

    get hasPasskey() {
        return this.securityKeyFactors.some((e) => e.isPasskey)
    }

    static async generateKeyAuthenticationOptions(
        req: Request,
        allowCredentials: AllowedCredential[],
        passkey: boolean,
    ) {
        const options = await generateAuthenticationOptions({
            allowCredentials,
            userVerification: passkey ? "preferred" : undefined,
            rpID,
        })

        req.session.twoFactor = {
            securityKey: {
                currentChallenge: options.challenge,
                challengeType: "authentication",
            },
        }
        return options
    }
    async generateKeyAuthenticationOptions(req: Request, passkey: boolean) {
        return TwoFactorSecurityKeyController.generateKeyAuthenticationOptions(
            req,
            this.allowCredentials,
            passkey,
        )
    }

    static async identifyKeyAuthentication(
        req: Request,
        tx: TransactionType = DBClient.getClient(),
    ) {
        const id = req.body.id
        if (typeof id !== "string") {
            throw new Error("did not find key ID in request")
        }

        const factor = await tx.secondAuthenticationFactor.findFirst({
            where: {
                type: "SecurityKey",
                keyPublicKeyId: id,
            },
        })
        if (!factor) {
            throw new Error("Passkey not found")
        }
        if (!factor.isPasskey) {
            throw new Error("2FA key found, but not set as passkey")
        }

        const controller = await TwoFactorController.fromUserId(
            factor.userId,
            tx,
        )
        if (!controller) {
            throw new Error("Did not find user corresponding to 2FA key")
        }

        await controller.securityKey.checkAndUpdateKeyAuthentication(
            req,
            true,
            factor.keyPublicKeyId!,
        )

        return controller.getUser()
    }
    async checkAndUpdateKeyAuthentication(
        req: Request,
        passkey: boolean,
        keyId?: string,
    ) {
        const clientChallenge =
            req.session.twoFactor?.securityKey?.currentChallenge
        if (
            typeof clientChallenge !== "string" ||
            req.session.twoFactor?.securityKey?.challengeType !==
                "authentication"
        ) {
            throw new Error(
                "challengeType not authentication, or currentChallenge not found",
            )
        }

        const matchingKey = this.securityKeyFactors.find(
            (f) =>
                f.keyPublicKeyId === keyId || f.keyPublicKeyId === req.body.id,
        )
        if (!matchingKey) {
            throw new Error("Did not match any saved 2FA keys")
        }

        const authnResult = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: clientChallenge,
            expectedOrigin: rpOrigin,
            expectedRPID: rpID,
            credential:
                TwoFactorSecurityKeyController.dbToCredential(matchingKey),
            requireUserVerification: passkey,
        })

        const { verified, authenticationInfo } = authnResult
        if (!verified || !authenticationInfo) {
            throw new Error("Authentication not verified")
        }

        await this.tx.secondAuthenticationFactor.update({
            where: {
                id: matchingKey.id,
            },
            data: {
                keyCounter: authenticationInfo.newCounter,
            },
        })
    }

    async generateKeyRegistrationOptions(req: Request, passkey: boolean) {
        const options = await generateRegistrationOptions({
            rpName,
            rpID,
            userID: Buffer.from(this.user.id, keyStorageEncoding),
            userName: this.user.displayName,
            attestationType: "none",
            authenticatorSelection: passkey
                ? {
                      residentKey: "required",
                      userVerification: "preferred",
                  }
                : {
                      userVerification: "discouraged",
                  },
            supportedAlgorithmIDs: [-7, -257],
        })

        req.session.twoFactor = {
            securityKey: {
                currentChallenge: options.challenge,
                challengeType: "registration",
            },
        }
        return options
    }

    async saveKeyRegistration(
        req: Request,
        keyData: RegistrationResponseJSON,
        nickname: string,
        passkey: boolean,
    ) {
        const clientChallenge =
            req.session.twoFactor?.securityKey?.currentChallenge
        if (
            typeof clientChallenge !== "string" ||
            req.session.twoFactor?.securityKey?.challengeType !== "registration"
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
                requireUserVerification: passkey,
            })
        } catch (e) {
            console.warn(e)
            return false
        }

        const { verified, registrationInfo } = registrationResult
        if (!verified || !registrationInfo) {
            return false
        }

        const dbAuthenticatorData =
            TwoFactorSecurityKeyController.credentialToDB(
                registrationInfo.credential,
            )
        if (dbAuthenticatorData.keyPublicKeyId === null) {
            throw new TypeError("keyPublicKeyId should not have been null")
        }

        const existingRegistration = this.securityKeyFactors.find(
            (f) => f.keyPublicKeyId === dbAuthenticatorData.keyPublicKeyId,
        )
        if (existingRegistration) {
            return false
        }

        await this.tx.secondAuthenticationFactor.create({
            data: {
                userId: this.user.id,
                type: "SecurityKey",
                ...dbAuthenticatorData,
                keyNickname: nickname,
                isPasskey: passkey,
            },
        })
        return true
    }
}
