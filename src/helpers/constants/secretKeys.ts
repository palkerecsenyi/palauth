import * as jose from "jose";

export const getSecretKeys = () => {
    const secrets = process.env["PAL_SECRETS"]
    if (!secrets) {
        throw new Error("PAL_SECRETS not defined")
    }

    const parsedSecrets = JSON.parse(secrets)
    if (!(parsedSecrets instanceof Array)) {
        throw new Error("PAL_SECRETS was not an array")
    }
    if (parsedSecrets.length === 0) {
        throw new Error("PAL_SECRETS was empty")
    }
    return parsedSecrets as string[]
}

const getJSONEnv = (env: string) => {
    const jwtKey = process.env[env]
    if (!jwtKey) {
        throw new Error(`${env} is not defined`)
    }
    const b = Buffer.from(jwtKey, "base64")
    const string = b.toString("utf-8")
    return JSON.parse(string)
}

const getJWT = (env: string) => {
    const json = getJSONEnv(env)
    return jose.importJWK(json, getJWKAlg())
}

export const getJWTPrivateKey = () => getJWT("PAL_PRIVATE_JWK")
export const getJWTPublicKey = () => getJWT("PAL_PUBLIC_JWK")
export const getJWTRawPublicKey = () => getJSONEnv("PAL_PUBLIC_JWK")
export const getJWKAlg = () => "RS256"

export const getHCaptchaSecret = () => process.env["PAL_HCAPTCHA_SECRET"]
