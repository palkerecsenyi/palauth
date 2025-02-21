import type {
    Prisma,
    SecondAuthenticationFactorType,
} from "../../database/generated-models/index.js"
import type { TransactionType } from "../../types/prisma.js"

export type UserWithSecondFactors = Prisma.UserGetPayload<{
    include: { secondFactors: true }
}>

export default abstract class BaseTwoFactorController {
    protected user: UserWithSecondFactors
    protected tx: TransactionType
    protected constructor(user: UserWithSecondFactors, tx: TransactionType) {
        this.user = user
        this.tx = tx
    }

    get factors() {
        return this.user.secondFactors
    }

    getUser() {
        return this.user
    }

    getFactor(type: SecondAuthenticationFactorType) {
        return this.factors.find((e) => e.type === type)
    }

    getFactors(type: SecondAuthenticationFactorType) {
        return this.factors.filter((e) => e.type === type)
    }

    registrationOfTypeExists(type: SecondAuthenticationFactorType) {
        return this.factors.some((e) => e.type === type)
    }
}
