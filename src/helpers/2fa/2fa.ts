import { TransactionType } from "../../types/prisma.js";
import { AuthenticatedRequest } from "../../types/express.js";
import { DBClient } from "../../database/client.js";
import BaseTwoFactorController, { UserWithSecondFactors } from "./general.js";
import TwoFactorSecurityKeyController from "./securityKey.js";

export default class TwoFactorController extends BaseTwoFactorController {
    private static async fromUserId(userId: string, tx: TransactionType) {
        const result = await tx.user.findFirst({
            where: {
                id: userId,
            },
            include: {
                secondFactors: true,
            }
        })

        if (!result) return undefined
        return new TwoFactorController(result, tx)
    }

    static fromAuthenticatedRequest(req: AuthenticatedRequest, tx: TransactionType = DBClient.getClient()) {
        return this.fromUserId(req.user!.id, tx)
    }

    static async mustFromAuthenticatedRequest(req: AuthenticatedRequest, tx: TransactionType = DBClient.getClient()) {
        const r = await this.fromAuthenticatedRequest(req, tx)
        if (!r) {
            throw new Error("Could not find user to create 2FA controller")
        }

        return r
    }

    static forUser(user: UserWithSecondFactors, tx: TransactionType = DBClient.getClient()) {
        return new TwoFactorController(user, tx)
    }

    private securityKeyController: TwoFactorSecurityKeyController | undefined = undefined
    public get securityKey() {
        if (!this.registrationOfTypeExists("SecurityKey")) {
            throw new Error("Method not supported")
        }

        if (!this.securityKeyController) {
            this.securityKeyController = new TwoFactorSecurityKeyController(this.user, this.tx)
        }

        return this.securityKeyController
    }
}
