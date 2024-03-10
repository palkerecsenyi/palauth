import { OAuthTokenType } from "../../database/generated-models/index.js"
import { DateTime, Duration } from "luxon"

export const sessionDurationMillis = () => 1 * 60 * 60 * 1000
export const sessionDuration = () =>
    Duration.fromMillis(sessionDurationMillis())

export const calculateTokenExpiry = (type: OAuthTokenType) => {
    if (type === "Refresh") {
        return DateTime.now().plus({ months: 6 })
    }

    if (type === "Access") {
        return DateTime.now().plus(sessionDuration())
    }

    throw new Error("Type was not valid")
}

export const authorizationCodeDuration = () =>
    Duration.fromObject({ minutes: 10 })
