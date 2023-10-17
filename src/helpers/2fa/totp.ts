import { Request } from "express";
import BaseTwoFactorController from "./general.js";
import speakeasy from "speakeasy"
import QRCode from "qrcode"

export default class TwoFactorTOTPController extends BaseTwoFactorController {
    private static secretSessionKey = "2fa_totp_secret"

    async generateSecret(req: Request) {
        const secret = speakeasy.generateSecret()

        const url = speakeasy.otpauthURL({
            secret: secret.ascii,
            issuer: "PalAuth",
            label: this.user.displayName,
        })

        req.session![TwoFactorTOTPController.secretSessionKey] = secret.ascii
        return {
            qrCodeUrl: await QRCode.toDataURL(url),
            rawSecret: secret.ascii,
        }
    }

    private verifySecret(token: string, secret: string) {
        return speakeasy.totp.verify({
            secret, token,
            encoding: "ascii",
            window: 2,
        })
    }

    async saveRegistration(token: string, req: Request) {
        const sessionSecret = req.session![TwoFactorTOTPController.secretSessionKey]
        if (typeof sessionSecret !== "string") {
            return false
        }

        const isValid = this.verifySecret(token, sessionSecret)
        if (!isValid) {
            return false
        }

        await this.tx.secondAuthenticationFactor.create({
            data: {
                userId: this.user.id,
                type: "TOTP",
                totpSecret: sessionSecret,
            }
        })
        return true
    }

    verify(token: string) {
        const factor = this.getFactor("TOTP")
        if (!factor) return false

        const secret = factor.totpSecret
        if (!secret) return false

        return this.verifySecret(token, secret)
    }
}
