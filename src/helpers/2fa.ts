import {Prisma, SecondAuthenticationFactorType} from "../database/generated-models/index.js";
import UserGetPayload = Prisma.UserGetPayload;
import {TransactionType} from "../types/prisma.js";
import {AuthenticatedRequest} from "../types/express.js";
import {DBClient} from "../database/client.js";
import {ExpectedAttestationResult, Fido2AttestationResult, Fido2Lib} from "fido2-lib";
import {getProjectHostname, getProjectOIDCID} from "./constants/hostname.js";
import {Request} from "express";

const f2l = new Fido2Lib({
    rpId: getProjectHostname(),
    rpName: "PalAuth",
    challengeSize: 128,
    attestation: "direct",
    authenticatorAttachment: "platform",
    authenticatorUserVerification: "preferred",
})

export type UserWithSecondFactors = UserGetPayload<{
    include: {secondFactors: true}
}>

export default class TwoFactorController {
    private user: UserWithSecondFactors
    private tx: TransactionType
    private constructor(user: UserWithSecondFactors, tx: TransactionType) {
        this.user = user
        this.tx = tx
    }

    private static async fromUserId(userId: string, tx: TransactionType) {
        const result = await tx.user.findFirst({
            where: {
                id: userId,
            },
            include: {
                secondFactors: true,
            }
        })

        if (!result) return undefined
        return new TwoFactorController(result, tx)
    }

    static fromAuthenticatedRequest(req: AuthenticatedRequest, tx: TransactionType = DBClient.getClient()) {
        return this.fromUserId(req.user!.id, tx)
    }

    static async mustFromAuthenticatedRequest(req: AuthenticatedRequest, tx: TransactionType = DBClient.getClient()) {
        const r = await this.fromAuthenticatedRequest(req, tx)
        if (!r) {
            throw new Error("Could not find user to create 2FA controller")
        }

        return r
    }

    get factors() {
        return this.user.secondFactors
    }

    registrationOfTypeExists(type: SecondAuthenticationFactorType) {
        return this.factors.some(e => e.type === type)
    }

    async generateKeyRegistrationOptions(req: Request) {
        const options = await f2l.attestationOptions()
        const encodedChallenge = Buffer.from(options.challenge).toString("base64")
        req.session!["2fa_key_challenge"] = encodedChallenge
        options.user.id = this.user.id
        options.user.name = this.user.displayName
        options.user.displayName = this.user.displayName
        return {
            ...options,
            challenge: encodedChallenge,
        }
    }

    async saveKeyRegistration(req: Request, clientResponse: any) {
        const clientChallenge = req.session!["2fa_key_challenge"]
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

        const isValidResponse = registrationResult.audit.complete && registrationResult.audit.validRequest && registrationResult.audit.validExpectations
        if (!isValidResponse) {
            return false
        }

        const counter = registrationResult.authnrData.get("counter") as number | undefined
        const publicKey = registrationResult.authnrData.get("credentialPublicKeyPem") as string | undefined

        if (typeof counter !== "number" || typeof publicKey !== "string") {
            return false
        }

        await this.tx.secondAuthenticationFactor.create({
            data: {
                userId: this.user.id,
                type: "SecurityKey",
                keyCounter: counter,
                keyPublicKey: publicKey,
            }
        })
        return true
    }
}