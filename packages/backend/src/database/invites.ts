import { TransactionType } from "../types/prisma.js"
import { DateTime } from "luxon"

export class InviteController {
    transaction: TransactionType
    constructor(tx: TransactionType) {
        this.transaction = tx
    }

    async deleteInvite(token: string) {
        await this.transaction.invite.delete({
            where: {
                token,
            },
        })
    }

    async lookupInvite(token: string) {
        const invite = await this.transaction.invite.findFirst({
            where: {
                token,
            },
        })

        if (!invite) return undefined

        if (
            invite.expires &&
            DateTime.fromJSDate(invite.expires) < DateTime.now()
        ) {
            await this.deleteInvite(invite.token)
            return undefined
        }

        if (invite.singleUse) {
            await this.deleteInvite(invite.token)
        }

        return invite
    }
}
