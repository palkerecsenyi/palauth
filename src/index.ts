import express from "express"
import cookieSession from "cookie-session"
import authRouter, {signOutRoute} from "./routes/auth.ts";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser"
import {getSecretKeys} from "./helpers/secretKeys.ts";
import flash from "connect-flash"
import testRouter from "./routes/test.ts";
import oidcRouter from "./routes/oidc.js";
import wellKnownRouter from "./routes/well-known.js";

const app = express()
app.set("view engine", "pug")
app.set("views", "./templates")

app.use(cookieSession({
    name: "pal_sesh",
    keys: getSecretKeys(),
    maxAge: 7 * 24 * 60 * 60 * 1000,
}))
app.use(bodyParser.urlencoded({
    extended: false,
}))
app.use(cookieParser())
app.use(flash())
app.use((req, res, next) => {
    res.locals.messages = req.flash()
    next()
})

app.use("/.well-known", wellKnownRouter)
app.use("/oidc", oidcRouter)
app.get("/auth/signout", signOutRoute)
app.use("/auth", authRouter)
app.use("/", testRouter)

app.listen(8080, () => {
    console.log("Listening :)")
})