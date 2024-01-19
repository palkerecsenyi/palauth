import { enroll } from "./enroll"
import { authenticate } from "./authenticate"

// @ts-expect-error
window["PAL_2FA_ENROLL"] = enroll
// @ts-expect-error
window["PAL_2FA_AUTHENTICATE"] = authenticate
