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

    static forUser(user: UserWithSecondFactors, tx: TransactionType = DBClient.getClient()) {
        return new TwoFactorController(user, tx)
    }

    get factors() {
        return this.user.secondFactors
    }

    getFactor(type: SecondAuthenticationFactorType) {
        return this.factors.find(e => e.type === type)
    }

    registrationOfTypeExists(type: SecondAuthenticationFactorType) {
        return this.factors.some(e => e.type === type)
    }

    private static keyRegistrationSessionKey = "2fa_key_reg_challenge"
    private static keyAuthenticationSessionKey = "2fa_key_auth_challenge"

    async generateKeyAuthenticationOptions(req: Request) {
        if (!this.registrationOfTypeExists("SecurityKey")) throw new Error("Method not supported")

        const options = await f2l.assertionOptions()
        const encodedChallenge = Buffer.from(options.challenge).toString("base64")
        req.session![TwoFactorController.keyAuthenticationSessionKey] = encodedChallenge

        const keyFactor = this.getFactor("SecurityKey")!
        const allowCredentials = [{
            type: "public-key",
            id: keyFactor.keyPublicKey,
        }]
        return {
            ...options,
            challenge: encodedChallenge,
            allowCredentials,
        }
    }

    async generateKeyRegistrationOptions(req: Request) {
        const options = await f2l.attestationOptions()
        const encodedChallenge = Buffer.from(options.challenge).toString("base64")
        req.session![TwoFactorController.keyRegistrationSessionKey] = encodedChallenge
        options.user.id = this.user.id
        options.user.name = this.user.displayName
        options.user.displayName = this.user.displayName
        return {
            ...options,
            challenge: encodedChallenge,
        }
    }

    async saveKeyRegistration(req: Request, clientResponse: any) {
        const clientChallenge = req.session![TwoFactorController.keyRegistrationSessionKey]
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
        const publicKey = registrationResult.authnrData.get("credId") as ArrayBuffer | undefined

        if (typeof counter !== "number" || !(publicKey instanceof ArrayBuffer)) {
            return false
        }

        await this.tx.secondAuthenticationFactor.create({
            data: {
                userId: this.user.id,
                type: "SecurityKey",
                keyCounter: counter,
                keyPublicKey: Buffer.from(publicKey).toString("base64"),
            }
        })
        return true
    }
}