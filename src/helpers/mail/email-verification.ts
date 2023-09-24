import {Prisma} from "../../database/generated-models/index.js";
import {DBClient} from "../../database/client.js";
import {DateTime} from "luxon";
import {EmailMessage} from "./message.js";
import {TransactionType} from "../../types/prisma.js";
import {randomInt} from "crypto";
import {ValidatedRequest} from "../../types/express.js";

class EmailVerificationMessage extends EmailMessage {
    constructor(code: string, to: string) {
        const subject = "Please verify your PalAuth account"
        const body = `Enter this code to verify your account: ${code}`

        super(to, subject, body);
    }
}

type EmailVerificationWithUser = Prisma.EmailVerificationGetPayload<{
    include: {user: true}
}>

export default class EmailVerificationController {
    private data: EmailVerificationWithUser
    private tx: TransactionType
    private constructor(data: EmailVerificationWithUser, tx: TransactionType) {
        this.data = data
        this.tx = tx
    }

    private static generateCode() {
        let code = ""
        for (let i = 0; i < 6; i++) {
            code += randomInt(10).toString()
        }

        return code
    }

    static async create(userId: string, tx: TransactionType = DBClient.getClient()) {
        const code = this.generateCode()

        const newInstance = await tx.emailVerification.create({
            data: {
                userId,
                code,
                expires: DateTime.now().plus({ minute: 10 }).toJSDate(),
            },
            include: {
                user: true,
            }
        })

        return new EmailVerificationController(newInstance, tx)
    }

    static async fromRequest(req: ValidatedRequest, tx: TransactionType = DBClient.getClient()) {
        const { code, email } = req.validatedData!
        const verification = await tx.emailVerification.findFirst({
            where: {
                code,
                user: {
                    email,
                }
            },
            include: {
                user: true,
            }
        })

        if (!verification) {
            return undefined
        }
        return new EmailVerificationController(verification, tx)
    }

    static async fromEmailAddress(emailAddress: string, tx: TransactionType = DBClient.getClient()) {
        const verification = await tx.emailVerification.findFirst({
            where: {
                user: {
                    email: emailAddress,
                }
            },
            include: {
                user: true,
            }
        })

        if (!verification) return undefined
        return new EmailVerificationController(verification, tx)
    }

    get code() {
        return this.data.code
    }

    async send() {
        const msg = new EmailVerificationMessage(this.code, this.data.user.email)
        await msg.send()
        await this.tx.emailVerification.update({
            where: {
                id: this.data.id,
            },
            data: {
                sentAt: new Date(),
            }
        })
    }

    async markVerified() {
        await this.tx.user.update({
            where: {
                id: this.data.userId,
            },
            data: {
                emailVerified: true,
            }
        })
        await this.tx.emailVerification.delete({
            where: {
                id: this.data.id,
            }
        })
    }
}