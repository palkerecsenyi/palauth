import express from "express"
import cookieSession from "cookie-session"
import authRouter, {signOutRoute} from "./routes/auth.js";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser"
import {getSecretKeys} from "./helpers/secretKeys.js";
import flash from "connect-flash"
import accountRouter from "./routes/account.js";
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
app.use("/", accountRouter)

const envPort = process.env["PORT"]
let port: number
if (envPort) {
    port = parseInt(envPort)
} else {
    port = 8080
}

app.listen(port, () => {
    console.log("Listening :)")
})