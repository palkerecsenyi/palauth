import {EmailVerification} from "../../database/generated-models/index.js";
import {DBClient} from "../../database/client.js";
import {DateTime} from "luxon";

export default class EmailVerificationController {
    private data: EmailVerification
    private constructor(data: EmailVerification) {
        this.data = data
    }

    static async create(userId: string) {
        const newInstance = await DBClient.getClient().emailVerification.create({
            data: {
                userId,
                expires: DateTime.now().plus({ minute: 10 }).toJSDate(),
            }
        })

        return new EmailVerificationController(newInstance)
    }

    get token() {
        return this.data.id
    }

    async send() {

    }
}