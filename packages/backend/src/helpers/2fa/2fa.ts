import { TransactionType } from "../../types/prisma.js"
import { AuthenticatedRequest } from "../../types/express.js"
import { DBClient } from "../../database/client.js"
import BaseTwoFactorController, { UserWithSecondFactors } from "./general.js"
import TwoFactorSecurityKeyController from "./securityKey.js"
import { $Enums } from "../../database/generated-models/index.js"
import TwoFactorTOTPController from "./totp.js"
import type {
    TwoFactorMethodController,
    TwoFactorMethodControllerInstance,
} from "./types.js"

export default class TwoFactorController extends BaseTwoFactorController {
    static async fromUserId(userId: string, tx: TransactionType) {
        const result = await tx.user.findFirst({
            where: {
                id: userId,
            },
            include: {
                secondFactors: true,
            },
        })

        if (!result) return undefined
        return new TwoFactorController(result, tx)
    }

    static fromAuthenticatedRequest(
        req: AuthenticatedRequest,
        tx: TransactionType = DBClient.getClient(),
    ) {
        return TwoFactorController.fromUserId(req.user!.id, tx)
    }

    static async mustFromAuthenticatedRequest(
        req: AuthenticatedRequest,
        tx: TransactionType = DBClient.getClient(),
    ) {
        const r = await TwoFactorController.fromAuthenticatedRequest(req, tx)
        if (!r) {
            throw new Error("Could not find user to create 2FA controller")
        }

        return r
    }

    static forUser(
        user: UserWithSecondFactors,
        tx: TransactionType = DBClient.getClient(),
    ) {
        return new TwoFactorController(user, tx)
    }

    private static controllerInitialisers: Record<
        $Enums.SecondAuthenticationFactorType,
        TwoFactorMethodController
    > = {
        SecurityKey: TwoFactorSecurityKeyController,
        TOTP: TwoFactorTOTPController,
    }
    private controller: Partial<
        Record<
            $Enums.SecondAuthenticationFactorType,
            TwoFactorMethodControllerInstance
        >
    > = {}
    private getController(type: $Enums.SecondAuthenticationFactorType) {
        if (!Object.hasOwn(this.controller, type)) {
            this.controller[type] =
                new TwoFactorController.controllerInitialisers[type](
                    this.user,
                    this.tx,
                )
        }

        return this.controller[type]
    }

    public get securityKey() {
        return this.getController(
            "SecurityKey",
        ) as TwoFactorSecurityKeyController
    }
    public get totp() {
        return this.getController("TOTP") as TwoFactorTOTPController
    }

    public async deleteFactor(id: string) {
        await this.tx.secondAuthenticationFactor.delete({
            where: {
                id,
            },
        })
    }
}
