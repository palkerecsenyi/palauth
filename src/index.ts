import express from "express"
import cookieSession from "cookie-session"
import * as process from "process";
import {DBClient} from "./database/client";

const app = express()
app.set("view engine", "pug")
app.set("views", "./templates")

const secrets = process.env["PAL_SECRETS"]
if (!secrets) {
    throw new Error("PAL_SECRETS not defined")
}
const parsedSecrets = JSON.parse(secrets)
app.use(cookieSession({
    name: "pal_sesh",
    keys: parsedSecrets,
    maxAge: 7 * 24 * 60 * 60 * 1000,
}))

const appListenPromise = () => new Promise<void>(resolve => {
    app.listen(8080, () => resolve())
})

async function main() {
    app.get("/", async (req, res) => {
        res.send("System ok :)")
    })

    app.get("/signin", async (req, res) => {
        res.render("signin")
    })

    await appListenPromise()
}

main()
    .then(async () => {
        await DBClient.disconnect()
    })
    .catch(async e => {
        console.error(e)
        await DBClient.disconnect()
        process.exit(1)
    })