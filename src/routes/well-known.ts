import express from "express";
import {getOIDCDiscoveryData} from "../helpers/oidc/discovery.js";

const wellKnownRouter = express.Router()

wellKnownRouter.get("/openid-configuration", (req, res) => {
    res.json(getOIDCDiscoveryData())
})

export default wellKnownRouter