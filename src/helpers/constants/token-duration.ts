import {OAuthTokenType} from "../../database/generated-models/index.js";
import {DateTime} from "luxon";

export const calculateTokenExpiry = (type: OAuthTokenType) => {
    if (type === "Refresh") {
        return DateTime.now().plus({ year: 1 })
    } else if (type === "Access") {
        return DateTime.now().plus({ days: 3 })
    }

    throw new Error("Type was not valid")
}