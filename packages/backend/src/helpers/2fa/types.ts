import TwoFactorSecurityKeyController from "./securityKey.js";
import TwoFactorTOTPController from "./totp.js";

export type TwoFactorMethodController = typeof TwoFactorSecurityKeyController | typeof TwoFactorTOTPController
export type TwoFactorMethodControllerInstance = TwoFactorSecurityKeyController | TwoFactorTOTPController
