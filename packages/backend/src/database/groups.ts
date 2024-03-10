import { TransactionType } from "../types/prisma.js"
import { DBClient } from "./client.js"
import { Group } from "./generated-models/index.js"
import { Pick } from "./generated-models/runtime/library.js"
import type { Request } from "express"

export default class GroupsController {
    private tx: TransactionType
    private managerUserId: string
    private constructor(managerUserId: string, tx: TransactionType) {
        this.managerUserId = managerUserId
        this.tx = tx
    }

    public static forUser(
        managerUserId: string,
        tx: TransactionType = DBClient.getClient(),
    ) {
        if (typeof managerUserId !== "string")
            throw new Error(
                "Tried to construct GroupsController with invalid user ID",
            )
        return new GroupsController(managerUserId, tx)
    }

    public static async listGroupsForToken(
        oauthClientId: string,
        userId: string,
        tx: TransactionType = DBClient.getClient(),
    ) {
        return tx.group.findMany({
            select: {
                systemName: true,
            },
            where: {
                onlyApplyTo: {
                    some: {
                        clientId: oauthClientId,
                    },
                },
                members: {
                    some: {
                        id: userId,
                    },
                },
            },
        })
    }

    public async listMyGroups() {
        return this.tx.group.findMany({
            where: {
                managedById: this.managerUserId,
            },
            include: {
                onlyApplyTo: true,
                members: true,
            },
        })
    }

    public async createGroup({
        systemName,
        displayName,
        description,
    }: Pick<Group, "systemName" | "displayName" | "description">) {
        const resp = await this.tx.group.create({
            data: {
                systemName,
                displayName,
                description,
                managedById: this.managerUserId,
            },
        })
        return resp.id
    }

    public async getGroup(id: string) {
        return this.tx.group.findFirst({
            where: {
                id,
                managedById: this.managerUserId,
            },
            include: {
                onlyApplyTo: true,
                members: true,
            },
        })
    }

    public async getGroupForRequest(req: Request) {
        const groupId = req.params.groupId
        if (typeof groupId !== "string") return null
        return this.getGroup(groupId)
    }

    public async deleteGroup(groupId: string) {
        await this.tx.group.delete({
            where: {
                id: groupId ?? "",
                managedById: this.managerUserId,
            },
        })
    }

    public async assignToGroup(userId: string, groupId: string) {
        return this.tx.group.update({
            where: {
                id: groupId ?? "",
                managedById: this.managerUserId,
            },
            data: {
                members: {
                    connect: {
                        id: userId,
                    },
                },
            },
        })
    }

    public async unassignFromGroup(userId: string, groupId: string) {
        return this.tx.group.update({
            where: {
                id: groupId ?? "",
                managedById: this.managerUserId,
            },
            data: {
                members: {
                    disconnect: {
                        id: userId,
                    },
                },
            },
        })
    }

    public async assignGroupToApp(clientId: string, groupId: string) {
        return this.tx.group.update({
            where: {
                id: groupId ?? "",
                managedById: this.managerUserId,
            },
            data: {
                onlyApplyTo: {
                    connect: {
                        clientId,
                    },
                },
            },
        })
    }

    public async unassignGroupFromApp(clientId: string, groupId: string) {
        return this.tx.group.update({
            where: {
                id: groupId ?? "",
                managedById: this.managerUserId,
            },
            data: {
                onlyApplyTo: {
                    disconnect: {
                        clientId,
                    },
                },
            },
        })
    }
}
