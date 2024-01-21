import express from "express";
import {getOIDCDiscoveryData} from "../helpers/oidc/discovery.js";
import {getJWTRawPublicKey} from "../helpers/constants/secretKeys.js";

const wellKnownRouter = express.Router()

wellKnownRouter.get("/openid-configuration", (_, res) => {
    res.json(getOIDCDiscoveryData())
})

wellKnownRouter.get("/jwks.json", async (_, res) => {
    const pubKey = getJWTRawPublicKey()
    res.json({
        keys: [pubKey]
    })
})

export default wellKnownRouter
