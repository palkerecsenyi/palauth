import * as jose from "jose"

export const getSecretKey = () => {
    const secret = process.env.PAL_SECRET
    if (!secret) {
        throw new Error("PAL_SECRET not defined")
    }

    if (secret.length === 0 || typeof secret !== "string") {
        throw new Error("PAL_SECRET was empty")
    }
    return secret
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

export const getCaptchaURL = () => process.env.PAL_CAPTCHA_URL
export const getCaptchaAPIKey = () => process.env.PAL_CAPTCHA_KEY

export const getMailgunHost = () => process.env.PAL_MAILGUN_HOST
export const getMailgunSecret = () => process.env.PAL_MAILGUN_KEY
export const getRedisSecret = () => process.env.PAL_REDIS_URL
