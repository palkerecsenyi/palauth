import express from "express"
import authRouter, {signOutRoute} from "./routes/auth.js";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser"
import {getCaptchaURL} from "./helpers/constants/secretKeys.js";
import flash from "connect-flash"
import accountRouter from "./routes/account.js";
import oidcRouter from "./routes/oidc.js";
import wellKnownRouter from "./routes/well-known.js";
import devRouter from "./routes/developer.js";
import DevModeSettings from "./helpers/constants/devMode.js";
import iamRouter from "./routes/iam.js";
import { initSessionManager } from "./helpers/session.js";

const app = express()
app.set("view engine", "pug")
app.set("views", "./templates")
app.use("/static", express.static("static"))

await initSessionManager(app)

app.use(bodyParser.urlencoded({
    extended: false,
}))
app.use(cookieParser())
app.use(flash())
app.use((req, res, next) => {
    res.locals.messages = req.flash()
    res.locals.disableCaptcha = DevModeSettings.isCaptchaDisabled()
    res.locals.captchaURL = getCaptchaURL()
    next()
})

app.use("/.well-known", wellKnownRouter)
app.use("/oidc", oidcRouter)
app.use("/dev", devRouter)
app.get("/auth/signout", signOutRoute)
app.use("/auth", authRouter)
app.get("/favicon.ico", (_, res) => res.sendStatus(404))
app.use("/iam", iamRouter)
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
