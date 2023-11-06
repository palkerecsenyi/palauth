declare module 'express-session' {
    interface SessionData {
        twoFactor: {
            securityKey?: {
                currentChallenge: string
                challengeType: "authentication" | "registration"
            }
        },
        signIn: {
            verifyEmail?: string
        }
    }
}
