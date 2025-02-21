import type { $Enums, Prisma } from "../../database/generated-models/index.js"
import { DBClient } from "../../database/client.js"
import { DateTime } from "luxon"
import { EmailMessage } from "./message.js"
import type { TransactionType } from "../../types/prisma.js"
import { randomInt } from "node:crypto"
import type { ValidatedRequest } from "../../types/express.js"

class VerificationEmailMessage extends EmailMessage {
    constructor(code: string, to: string) {
        const subject = "Please verify your PalAuth account"
        const body = `Enter this code to verify your account: ${code}`

        super(to, subject, body)
    }
}

type VerificationMessageWithPayload = Prisma.VerificationMessageGetPayload<{
    include: { user: true }
}>

export default class VerificationMessageController {
    private data: VerificationMessageWithPayload
    private tx: TransactionType
    private constructor(
        data: VerificationMessageWithPayload,
        tx: TransactionType,
    ) {
        this.data = data
        this.tx = tx
    }

    get userId() {
        return this.data.user.id
    }

    private static generateCode() {
        let code = ""
        for (let i = 0; i < 6; i++) {
            code += randomInt(10).toString()
        }

        return code
    }

    static async create(
        userId: string,
        purpose: $Enums.VerificationMessagePurpose,
        tx: TransactionType = DBClient.getClient(),
    ) {
        const code = VerificationMessageController.generateCode()

        // Delete all existing verifications first
        await tx.verificationMessage.deleteMany({
            where: {
                userId,
                purpose,
            },
        })

        const newInstance = await tx.verificationMessage.create({
            data: {
                purpose,
                userId,
                code,
                expires: DateTime.now().plus({ minute: 10 }).toJSDate(),
            },
            include: {
                user: true,
            },
        })

        return new VerificationMessageController(newInstance, tx)
    }

    private static validateVerificationMessage(
        vm: VerificationMessageWithPayload | null,
        purpose: $Enums.VerificationMessagePurpose,
    ): vm is VerificationMessageWithPayload {
        if (!vm) return false
        if (vm.purpose !== purpose) return false
        if (DateTime.fromJSDate(vm.expires) < DateTime.now()) return false

        return true
    }

    static async fromRequest(
        req: ValidatedRequest,
        purpose: $Enums.VerificationMessagePurpose,
        tx: TransactionType = DBClient.getClient(),
    ) {
        const { code, email } = req.validatedData!
        const verification = await tx.verificationMessage.findFirst({
            where: {
                code,
                user: {
                    email,
                },
            },
            include: {
                user: true,
            },
        })

        if (
            !VerificationMessageController.validateVerificationMessage(
                verification,
                purpose,
            )
        )
            return undefined
        return new VerificationMessageController(verification, tx)
    }

    static async fromEmailAddress(
        emailAddress: string,
        purpose: $Enums.VerificationMessagePurpose,
        tx: TransactionType = DBClient.getClient(),
    ) {
        const verification = await tx.verificationMessage.findFirst({
            where: {
                user: {
                    email: emailAddress,
                },
            },
            include: {
                user: true,
            },
        })

        if (
            !VerificationMessageController.validateVerificationMessage(
                verification,
                purpose,
            )
        )
            return undefined
        return new VerificationMessageController(verification, tx)
    }

    get code() {
        return this.data.code
    }

    async send() {
        const msg = new VerificationEmailMessage(
            this.code,
            this.data.user.email,
        )
        await msg.send()
        await this.tx.verificationMessage.update({
            where: {
                id: this.data.id,
            },
            data: {
                sentAt: new Date(),
            },
        })
    }

    async delete() {
        await this.tx.verificationMessage.delete({
            where: {
                id: this.data.id,
            },
        })
    }
}
