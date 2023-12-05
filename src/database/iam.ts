import { TransactionType } from "../types/prisma.js";
import { DBClient } from "./client.js";
import { Prisma } from "./generated-models/index.js";

export type IAMControllerRoleType = Prisma.IAMRoleGetPayload<{
    include: {permissions: true}
}>

export default class IAMController {
    private clientId: string
    private roles: IAMControllerRoleType[]
    private tx: TransactionType
    private constructor(clientId: string, roles: IAMControllerRoleType[], tx: TransactionType) {
        this.clientId = clientId
        this.roles = roles
        this.tx = tx
    }

    static async forOAuthClient(clientId: string, tx: TransactionType = DBClient.getClient()) {
        const scopes = await tx.iAMRole.findMany({
            where: {
                ownerId: clientId,
            },
            include: {
                permissions: true,
            }
        })
        return new IAMController(clientId, scopes, tx)
    }

    listPermissions() {
        return this.tx.iAMPermission.findMany({
            where: {
                ownerId: this.clientId,
            },
        })
    }

    private findRoleByName(roleName: string) {
        return this.roles.find(r => r.name === roleName)
    }

    listRoles() {
        return this.roles
    }

    listRolesForUser(userId: string) {
        return this.tx.iAMRole.findMany({
            where: {
                assignments: {
                    every: {
                        userId,
                    }
                }
            },
            include: {
                permissions: true,
            }
        })
    }

    listAllUsersWithRoles() {
        return this.tx.user.findMany({
            where: {
                iamRoles: {
                    some: {
                        role: {
                            ownerId: this.clientId,
                        }
                    }
                }
            },
            include: {
                iamRoles: {
                    include: {
                        role: true,
                    }
                },
            }
        })
    }

    async checkPermission(request: {
        userId: string,
        permissionName: string,
    }) {
        const role = await this.tx.iAMRole.findFirst({
            where: {
                permissions: {
                    some: {
                        name: request.permissionName,
                        ownerId: this.clientId,
                    }
                },
                assignments: {
                    some: {
                        userId: request.userId,
                    }
                },
                ownerId: this.clientId,
            }
        })

        return role !== null
    }

    async createPermission(name: string) {
        const permission = await this.tx.iAMPermission.create({
            data: {
                name,
                ownerId: this.clientId,
            }
        })

        return permission.id
    }

    async assignRoleByName(request: {
        userId: string,
        roleName: string,
    }) {
        const role = this.findRoleByName(request.roleName)
        if (!role) {
            throw new Error("Role not found")
        }

        await this.tx.iAMRoleAssignment.upsert({
            where: {
                userId_roleId: {
                    userId: request.userId,
                    roleId: role.id,
                }
            },
            update: {},
            create: {
                userId: request.userId,
                roleId: role.id,
            }
        })
    }

    async removeRoleByName(request: {
        userId: string,
        roleName: string,
    }) {
        const role = this.findRoleByName(request.roleName)
        if (!role) {
            throw new Error("Role not found")
        }

        await this.tx.iAMRoleAssignment.delete({
            where: {
                userId_roleId: {
                    userId: request.userId, 
                    roleId: role.id
                }
            }
        })
    }
}
