import type { OIDCFlowData } from "../helpers/oidc/oidc-flow.js"

declare module "express-session" {
    interface SessionData {
        twoFactor: {
            securityKey?: {
                currentChallenge: string
                challengeType: "authentication" | "registration"
            }
            totp?: {
                secret: string
            }
        }
        signIn: {
            verifyEmail?: string
            userID?: string
            provisionalUserID?: string
        }
        oidcFlow: OIDCFlowData
        flow: {
            [key: string]: string
        }
    }
}
