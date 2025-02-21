import type TwoFactorSecurityKeyController from "./securityKey.js"
import type TwoFactorTOTPController from "./totp.js"

export type TwoFactorMethodController =
    | typeof TwoFactorSecurityKeyController
    | typeof TwoFactorTOTPController
export type TwoFactorMethodControllerInstance =
    | TwoFactorSecurityKeyController
    | TwoFactorTOTPController
