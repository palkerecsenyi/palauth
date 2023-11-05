import { Express } from "express";
import expressSession from "express-session";
import { sessionDurationMillis } from "./constants/token-duration.js";
import { getSecretKeys } from "./constants/secretKeys.js";
import RedisStore from "connect-redis"
import { createClient } from "redis";

export const initSessionManager = async (app: Express) => {
    const redisClient = createClient()
    await redisClient.connect()

    app.use(expressSession({
        cookie: {
            maxAge: sessionDurationMillis(),
            sameSite: "lax",
            httpOnly: true,
        },
        name: "palauth_sesh_id",
        secret: getSecretKeys(),
        saveUninitialized: true,
        resave: false,
        store: new RedisStore({
            client: redisClient,
            prefix: "palauth:",
        })
    }))
}
