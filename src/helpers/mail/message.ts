import Mailgun from "mailgun.js";
import * as FormData from "form-data";
import {getMailgunSecret} from "../constants/secretKeys.js";

const mailgun = new Mailgun(FormData)
const mg = mailgun.client({
    url: "https://api.eu.mailgun.com",
    username: "api",
    key: getMailgunSecret(),
})

export abstract class EmailMessage {
    private to: string
    private subject: string
    private body: string

    protected constructor(to: string, subject: string, body: string) {
        this.to = to
        this.subject = subject
        this.body = body
    }

    send() {
        return mg.messages.create("auth.palk.me", {
            from: "PalAuth <noreply@auth.palk.me>",
        })
    }
}