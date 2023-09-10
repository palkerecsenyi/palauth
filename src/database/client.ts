import {PrismaClient} from "./generated-models/index.js";
import {TransactionType} from "../types/prisma.js";

class TransactionInterruptError extends Error {
    constructor() {
        super("TRANSACTION_INTERRUPT");
    }
}

interface InterruptibleTransaction extends TransactionType {
    rollback(): void
}

export class DBClient {
    private static client: PrismaClient = new PrismaClient()
    private static disconnected = false
    static getClient() {
        if (this.disconnected) {
            throw new Error("tried to use Prisma client after disconnect")
        }
        return this.client
    }
    static async disconnect() {
        if (this.disconnected) {
            throw new Error("tried to disconnect already disconnected Prisma client")
        }
        await this.client.$disconnect()
        this.disconnected = true
    }

    static async interruptibleTransaction<T>(callback: (tx: InterruptibleTransaction) => Promise<T>) {
        const client = DBClient.getClient()
        try {
            return await client.$transaction(async tx => {
                return callback({
                    ...tx,
                    rollback() {
                        throw new TransactionInterruptError()
                    }
                })
            })
        } catch (e) {
            if (e instanceof TransactionInterruptError) {
                return undefined
            }
        }
    }
}