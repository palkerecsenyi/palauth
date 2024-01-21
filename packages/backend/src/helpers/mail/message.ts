import Mailgun from "mailgunjs";
import * as FormData from "form-data";
import { getMailgunHost, getMailgunSecret } from "../constants/secretKeys.js";

// @ts-ignore
const mailgun = new Mailgun(FormData.default)
const mg = mailgun.client({
    url: "https://api.eu.mailgun.net",
    username: "api",
    key: getMailgunSecret(),
})

export abstract class EmailMessage {
    private readonly to: string
    private readonly subject: string
    private readonly body: string

    protected constructor(to: string, subject: string, body: string) {
        this.to = to
        this.subject = subject
        this.body = body
    }

    send() {
        return mg.messages.create(getMailgunHost(), {
            from: `PalAuth <noreply@${getMailgunHost()}>`,
            to: this.to,
            subject: this.subject,
            text: this.body,
        })
    }
}
