export default class DevModeSettings {
    private static allowed(variable: string) {
        const variableTrue = process.env[`PAL_DEV_${variable}`] === "true"

        if (!variableTrue) return false
        if (process.env.NODE_ENV !== "development") {
            throw new Error("tried to use dev mode overrides in live mode")
        }
        return true
    }

    public static isCaptchaDisabled() {
        return DevModeSettings.allowed("CAPTCHA_DISABLE")
    }
    public static isInsecurePasswordsAllowed() {
        return DevModeSettings.allowed("ALLOW_INSECURE_PASSWORD")
    }
    public static skipEmailVerification() {
        return DevModeSettings.allowed("SKIP_EMAIL_VERIFICATION")
    }
    public static isNodeDevMode() {
        return process.env.NODE_ENV === "development"
    }
}
