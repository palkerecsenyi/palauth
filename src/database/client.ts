import {PrismaClient} from "./generated-models";

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
}