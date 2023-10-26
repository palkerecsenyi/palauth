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

    private async getRoleAssignment(userId: string, roleId: string) {
        return this.tx.iAMRoleAssignment.findFirst({
            where: {
                userId, roleId,
            }
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

    async checkPermission(request: {
        userId: string,
        permissionName: string,
    }) {
        const matchingRole = this.roles.find(role => {
            const matchingPermission = role.permissions.find(perm => {
                return perm.name === request.permissionName
            })

            return matchingPermission !== undefined
        })

        if (!matchingRole) return false
        const roleAssignment = await this.getRoleAssignment(request.userId, matchingRole.id)
        return roleAssignment !== undefined
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